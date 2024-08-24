import json
import requests
import csv
from shodan import Shodan, APIError
from concurrent.futures import ThreadPoolExecutor, as_completed


class ElasticSearchNoAuth:
    def __init__(self):
        self.api = Shodan('')
        self.limit = 0
        self.es_urls = []

    @staticmethod
    def list_indices(es_url, timeout=5, retries=3):
        attempt = 0
        while attempt < retries:
            try:
                response = requests.get(f'{es_url}/_cat/indices?format=json', timeout=timeout)
                response.raise_for_status()
                return [index['index'] for index in response.json()]
            except requests.exceptions.Timeout:
                print(f"Connection to {es_url} timed out. Retrying... ({attempt + 1}/{retries})")
                attempt += 1
            except requests.exceptions.RequestException as err:
                print(f"HTTP error occurred: {err}")
                return []
            except Exception as err:
                print(f"Other error occurred: {err}")
                return []
        return []

    @staticmethod
    def search_index(es_url, index_name, query, size=500, timeout=5):
        try:
            response = requests.get(f'{es_url}/{index_name}/_search', json=query, params={'size': size}, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')
            print(response.text)
            return {}
        except Exception as err:
            print(f'Other error occurred: {err}')
            return {}

    def get_shodan(self, workers):
        self.limit = workers
        try:
            results = self.api.search_cursor('elasticsearch -authentication')
            if results:
                for banner in results:
                    try:
                        ip = banner.get('ip_str')
                        country_code = banner.get('location', {}).get('country_code')
                        port = banner.get('port')

                        if not ip or not port:
                            print("IP address or port not found in the banner.")
                            continue

                        es_url = f'http://{ip}:{port}'
                        self.es_urls.append({'url': es_url, 'ip': ip, 'port': port})
                        print(f"{ip} || {country_code} || {port}")

                        if len(self.es_urls) >= self.limit:
                            break
                    except (KeyError, TypeError, json.JSONDecodeError) as e:
                        print(f"Error parsing Shodan banner: {e}")
                        continue
            else:
                print("No results from Shodan API.")

        except APIError as e:
            print(f"Shodan API Error: {e}")
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def dump_index_to_csv(self, es_url, ip, port, index_name):
        query = {'query': {'match_all': {}}}
        response = self.search_index(es_url, index_name, query)

        if not response:
            print(f"Error retrieving data from index '{index_name}' on {es_url}.")
            return

        csv_filename = f"{ip}_{port}_{index_name}.csv"

        try:
            with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)

                headers_written = False
                for hit in response.get('hits', {}).get('hits', []):
                    document = hit.get('_source', {})
                    if not headers_written:
                        headers = list(document.keys())
                        writer.writerow(headers)
                        headers_written = True

                    writer.writerow(list(document.values()))

            print(f"Index '{index_name}' saved to '{csv_filename}'.")
        except Exception as e:
            print(f"Error writing to CSV file: {e}")

    def run_elastic_search_auth_proc(self, workers):
        try:
            self.get_shodan(workers)
            if not self.es_urls:
                print("No Elasticsearch instances found.")
                return

            for es_data in self.es_urls:
                es_url = es_data['url']
                ip = es_data['ip']
                port = es_data['port']

                available_indices = self.list_indices(es_url)
                if not available_indices:
                    print(f"No indices found for {es_url} or an error occurred.")
                    continue

                print(f"Available indexes for {es_url}: {available_indices}")

                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [
                        executor.submit(self.dump_index_to_csv, es_url, ip, port, index_name)
                        for index_name in available_indices
                    ]

                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"An error occurred during the thread execution: {e}")

        except Exception as e:
            print(f"An unexpected error occurred with Elasticsearch: {e}")



