import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class Scanner:
    def __init__(self, url):
        self.target_url = url
        self.subdomains = []
        self.links_list = [url]
        self.extract_subdomains()
        self.crawl()

    def add_http(self, url):
        return url if "http" in url else f"http://{url}"

    def get_request(self, url):
        try:
            return requests.get(self.add_http(url))
        except requests.exceptions.ConnectionError:
            pass

    def extract_forms(self, url):
        response = self.get_request(url)
        parsed_html = BeautifulSoup(response.content, features="html.parser")
        forms_list = parsed_html.findAll("form")
        return forms_list

    def submit_form(self,  form, url, payload):
        action = form.get("action")
        method = form.get("method")
        inputs_list = form.findAll("input")
        post_url = urljoin(url, action)
        post_data = {}  # our dictionary

        for input in inputs_list:
            name = input.get("name")
            _type = input.get("type")
            value = input.get("value")
            if _type == "text" or _type == "password":
                post_data[name] = payload
            else:
                post_data[name] = value

        if method == "post" or method == "POST":
            return requests.post(post_url, data=post_data)
        else:
            return requests.get(post_url, params=post_data)

    def extract_links(self, url):
        url = self.add_http(url)
        response = self.get_request(url)
        parsed_html = BeautifulSoup(response.content, features="html.parser")
        found_links_list = parsed_html.findAll("a")
        pages_list = []
        for link in found_links_list:
            href = link.get("href")
            if "http" not in href:
                page = urljoin(url, href)
                try:
                    requests.get(page)
                    pages_list.append(page)
                except:
                    pass
        return pages_list

    def extract_subdomains(self):
        with open("./subdomains.txt", "r") as file:
            for line in file:
                line = line.strip() + "."
                subdomain = self.add_http(line + self.target_url)
                try:
                    requests.get(subdomain)
                    self.subdomains.append(subdomain)
                    self.links_list.append(subdomain)
                except:
                    pass

    def crawl(self):
        for link in self.links_list:
            new_lst = self.extract_links(link)
            for new in new_lst:
                if new not in self.links_list:
                    print(new)
                    self.links_list.append(new)
