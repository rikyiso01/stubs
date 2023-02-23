from requests import Session
from bs4 import BeautifulSoup
from re import compile
from json import loads
from os import environ

URL = "https://easyacademy.unige.it/portalestudenti/index.php?view=prenotalezione&include=prenotalezione&_lang=it"
LOGIN_URL = "https://easyacademy.unige.it/auth/auth_app2.php?response_type=token&client_id=client&redirect_uri=https://easyacademy.unige.it/portalestudenti/index.php?view=login&scope=openid+profile"
POST_URL = "https://unigepass.unige.it/idp/module.php/core/loginuserpass.php?"
SAML_URL = (
    "https://easyacademy.unige.it/simplesaml/module.php/saml/sp/saml2-acs.php/UniGePASS"
)
USERNAME = environ["UNIGE_USERNAME"]
PASSWORD = environ["UNIGE_PASSWORD"]

POST_DATA = "username={}&password={}&RelayState=&AuthState={}"
EASY_ACADEMY_TOKEN = "https://easyacademy.unige.it/auth/auth_app_redirect.php"
REDIRECT_VALUE = "https://easyacademy.unige.it/portalestudenti/index.php?view=login"

FINAL_LOGIN = (
    "https://easyacademy.unige.it/portalestudenti/login.php?from=&from_include="
)
ACCESS_TOKEN = "ikisdfhiodshfo.eyJzdXJuYW1lIjoiSXNvbGEiLCJuYW1lIjoiUmljY2FyZG8iLCJmaXNjYWxDb2RlIjoiNDk0MzM2OSIsIm1haWwiOiI0OTQzMzY5QHN0dWRlbnRpLnVuaWdlLml0IiwibWF0cmljb2xhIjoiNDk0MzM2OSJ9.dbnifjsd"

JSON_REGEX = compile("var lezioni_prenotabili = JSON.parse\\(.*;")
JSON_OFFSET = len("var lezioni_prenotabili = JSON.parse('")

BOOKING_URL = f"https://easyacademy.unige.it/portalestudenti/call_ajax.php?mode=salva_prenotazioni&codice_fiscale={USERNAME[1:]}&id_entries=[{'{0}'}]&id_btn_element={'{0}'}"


def main():
    session = Session()
    session.get(URL)
    soup = BeautifulSoup(session.get(LOGIN_URL).text, features="html.parser")
    auth_state = soup("input", {"name": "AuthState"})[0]["value"]
    response = session.post(
        POST_URL,
        data={
            "username": USERNAME,
            "password": PASSWORD,
            "RelayState": "",
            "AuthState": auth_state,
        },
    )
    soup = BeautifulSoup(response.text, features="html.parser")
    saml = soup("input", {"name": "SAMLResponse"})[0]["value"]
    response = session.post(SAML_URL, data={"SAMLResponse": saml})
    soup = BeautifulSoup(response.text, features="html.parser")
    access_token = soup("input", {"name": "access_token"})[0]["value"]
    response = session.post(
        EASY_ACADEMY_TOKEN,
        data={"access_token": access_token, "redirect": REDIRECT_VALUE},
    )
    response = session.post(FINAL_LOGIN, data={"access_token": access_token})
    response = session.get(URL)
    text = response.text
    search = JSON_REGEX.search(text)
    assert search is not None
    json = loads(text[search.start() + JSON_OFFSET : search.end() - 4])
    for group in json:
        for lesson in group["prenotazioni"]:
            if not lesson["prenotata"]:
                if lesson["nome"] == "BASI DI DATI" and lesson["aula"] in [
                    "Aula 711",
                    "Aula 218",
                ]:
                    continue
                id = lesson["entry_id"]
                print("Booking", id)
                session.get(BOOKING_URL.format(id))
    print("No more lessons to book")


if __name__ == "__main__":
    main()
