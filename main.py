import requests

# Замените 'YOUR_API_KEY' на ваш реальный ключ API VirusTotal
API_KEY = 'YOUR_API_KEY'
URL = 'https://www.virustotal.com/vtapi/v2/url/report'

def check_url(url):
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get(URL, params=params)
    return response.json()

if __name__ == '__main__':
    url_to_check = 'http://www.example.com'
    report = check_url(url_to_check)
    print(report)
