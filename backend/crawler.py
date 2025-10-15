import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
import os

class LinkSpider(CrawlSpider):
    name = 'link_spider'

    def __init__(self, start_url, allowed_domains, *args, **kwargs):
        self.start_urls = [start_url]
        self.allowed_domains = allowed_domains
        LinkSpider.rules = (
            Rule(LinkExtractor(allow_domains=self.allowed_domains), callback='parse_item', follow=True),
        )
        super(LinkSpider, self).__init__(*args, **kwargs)

    def parse_item(self, response):
        yield {
            'url': response.url,
        }

def start_crawl(start_url, allowed_domain, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    process = CrawlerProcess(settings={
        "FEEDS": {
            output_file: {"format": "json"},
        },
        "LOG_LEVEL": "INFO",
        "CLOSESPIDER_ITEMCOUNT": 100,
        "USER_AGENT": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    })

    process.crawl(LinkSpider, start_url=start_url, allowed_domains=[allowed_domain])
    process.start()
