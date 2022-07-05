import urllib.request


def invoke_http_request():
    print('(python user space): Invoking http request...')
    with urllib.request.urlopen("http://example.com/") as response:
        print('(python user space): Received HTTP response')
        html = response.read()
        print(html)


if __name__ == "__main__":
    invoke_http_request()
