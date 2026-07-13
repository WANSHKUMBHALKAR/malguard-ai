import os
import urllib.request

def download_dataset():
    url = "https://raw.githubusercontent.com/Anustup900/Automated-Malware-Analysis/master/dataset_malwares.csv"
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "api", "data")
    output_path = os.path.join(output_dir, "malware_dataset.csv")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"Downloading real malware dataset from: {url}")
    print("This may take a few moments...")
    
    try:
        urllib.request.urlretrieve(url, output_path)
        print(f"Dataset successfully downloaded and saved to: {output_path}")
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        print("Please check internet connection or download the file manually and save it to api/data/malware_dataset.csv")

if __name__ == "__main__":
    download_dataset()
