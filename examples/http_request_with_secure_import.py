from secimport import secure_import

http_request = secure_import(
    "http_request",
    allow_shells=False,
    allow_networking=False,
)

if __name__ == "__main__":
    http_request.invoke_http_request()
