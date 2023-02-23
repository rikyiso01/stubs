from gdown import download as gdown
from subprocess import check_call
from tempfile import NamedTemporaryFile


def download():
    files = {
        "er": "https://drive.google.com/uc?id=1tcfjGTeIVZ62J8XL63CgYYFmf36Vp1Jw",
        "er-ristrutturato": "https://drive.google.com/uc?id=1BD9_TbXhhrvwcFzMc-mX5tKPhnXUNzLY",
    }
    for name, url in files.items():
        tmp = NamedTemporaryFile(delete=False)
        tmp.close()
        gdown(
            url,
            tmp.name,
        )
        check_call(f"drawio {tmp.name} -f svg -o out/{name}.svg -x", shell=True)
