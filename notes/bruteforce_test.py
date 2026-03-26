import requests

login_url = "http://127.0.0.1:5000/login"

email = "ellisarm6@gmail.com"

passwords = [
    "test1",
    "123456",
    "password",
    "qwerty",
    "admin",
    "ellis123",
    "admin",
    "admin",
    "admin",
    "admin"

]

attempt = 1

for password in passwords:
    print(f"Attempt #{attempt}")
    attempt += 1
    response = requests.post(login_url, data={
        "email": email,
        "password": password
    }, allow_redirects=False)

    print("Trying password:", password)
    print("Status code:", response.status_code)

    if response.status_code == 302:
        print("Result: login success")

    elif "Invalid credentials" in response.text:
        print("Result: invalid credentials")

    else:
        print("Result:", response.text.strip())


    print("-" * 40)