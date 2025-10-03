from dns import resolver, exception
import time
from asyncio.subprocess import PIPE, create_subprocess_exec
from requests.exceptions import ConnectionError
from lumen_src.utils.help_utils import HelpUtilities
from lumen_src.utils.exceptions import LumenException
from lumen_src.utils.logger import Logger, SystemOutLogger
from lumen_src.utils.coloring import COLOR, COLORED_COMBOS
from requests_doh import DNSOverHTTPSSession  # Requires pip install requests-doh

stdout_logger = SystemOutLogger()


class DNSHandler:
    resolver = resolver.Resolver()

    @classmethod
    def set_nameservers(cls, nameservers):
        cls.resolver.nameservers = nameservers

    @classmethod
    def query_dns(cls, domains, records, use_tcp=False, follow_cname=True):
        results = {k: set() for k in records}
        for record in records:
            for domain in domains:
                try:
                    answers = cls.resolver.resolve(domain, record, tcp=use_tcp)
                    for answer in answers:
                        results.setdefault(record, set()).add(str(answer))
                        if follow_cname and record == 'CNAME':
                            # Recursively query the CNAME target
                            cname_results = cls.query_dns([str(answer)], records, use_tcp)
                            for cname_record, cname_values in cname_results.items():
                                results.setdefault(cname_record, set()).update(cname_values)
                except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers, exception.Timeout):
                    continue
        return {k: v for k, v in results.items() if v}

    @classmethod
    def robust_query_dns(cls, domains, records, max_retries=3):
        resolvers = [['8.8.8.8', '8.8.4.4'], ['1.1.1.1', '1.0.0.1']]  # Google and Cloudflare
        for attempt in range(max_retries):
            try:
                return cls.query_dns(domains, records)
            except exception.Timeout:
                stdout_logger.error(f"DNS Query timed out (attempt {attempt + 1}). Retrying...")
                cls.set_nameservers(resolvers[attempt % len(resolvers)])
                time.sleep(2 ** attempt)  # Exponential backoff
        # Final fallback to DoH
        stdout_logger.info("Switching to DNS over HTTPS as final fallback...")
        return cls.query_doh(domains, records)

    @classmethod
    def query_doh(cls, domains, records):
        results = {k: set() for k in records}
        session = DNSOverHTTPSSession(provider='cloudflare')  # Or 'google'
        for record in records:
            for domain in domains:
                try:
                    # Use session to resolve (adapt based on your needs)
                    response = session.resolve(domain, rdtype=record)
                    for answer in response.answer:
                        results.get(record).add(str(answer))
                except Exception:
                    continue
        return {k: v for k, v in results.items() if v}

    @classmethod
    def enumerate_subdomains(cls, domain, wordlist_path, records=['A', 'CNAME']):
        with open(wordlist_path, 'r') as f:
            subdomains = [f"{line.strip()}.{domain}" for line in f if line.strip()]
        return cls.robust_query_dns(subdomains, records)

    @classmethod
    def attempt_zone_transfer(cls, domain, nameserver):
        try:
            zone = resolver.zone_for_name(domain, resolver=cls.resolver, tcp=True)
            return {str(rrset.name): str(rrset) for rrset in zone}
        except (resolver.NoNameservers, resolver.NXDOMAIN):
            stdout_logger.error("Zone transfer failed")
            return {}

    @classmethod
    async def grab_whois(cls, host):
        if not host.naked:
            return

        script = "whois {}".format(host.naked).split()
        log_file = HelpUtilities.get_output_path("{}/whois.txt".format(host.target))
        logger = Logger(log_file)

        process = await create_subprocess_exec(
            *script,
            stdout=PIPE,
            stderr=PIPE
        )
        result, err = await process.communicate()

        if process.returncode == 0:
            logger.info("{} {} WHOIS information retrieved".format(COLORED_COMBOS.GOOD, host))
            for line in result.decode().strip().split("\n"):
                if ":" in line:
                    logger.debug(line)

    @classmethod
    async def generate_dns_dumpster_mapping(cls, host, sout_logger):
        sout_logger.info("{} Trying to fetch DNS Mapping for {} from DNS dumpster".format(
            COLORED_COMBOS.INFO, host))
        try:
            page = HelpUtilities.query_dns_dumpster(host=host)
            if page.status_code == 200:
                path = HelpUtilities.get_output_path("{}/dns_mapping.png".format(host.target))
                with open(path, "wb") as target_image:
                    target_image.write(page.content)
                sout_logger.info("{} Successfully fetched DNS mapping for {}".format(
                    COLORED_COMBOS.GOOD, host.target)
                )
            else:
                raise LumenException
        except LumenException:
            sout_logger.info("{} Failed to generate DNS mapping. A connection error occurred.".format(
                COLORED_COMBOS.BAD))
