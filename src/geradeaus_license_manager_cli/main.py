import typer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import uuid
from pathlib import Path
from typing import Optional
from typing_extensions import Annotated
import jwt


app = typer.Typer()


@app.command()
def generate_rsa(path: Annotated[Optional[Path], typer.Option()] = None):
    if path is None:
        path = Path('.')
    if path.is_file():
        print("Path must be a directory, but is a file.")
        raise typer.Abort()
    elif path.is_dir():
        pass
    elif not path.exists():
        print("Path does not exist.")
        raise typer.Abort()

    path = path / str(uuid.uuid4())
    path.mkdir()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    numbers = public_key.public_numbers()
    exponent_b64 = base64.b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8')
    modulus_b64 = base64.b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8')
    public_key_xml = f"<RSAKeyValue><Modulus>{modulus_b64}</Modulus><Exponent>{exponent_b64}</Exponent></RSAKeyValue>"

    with (path / "private_key.pem").open("w", encoding ="utf-8") as file:
        file.write(private_pem.decode('utf-8'))

    with (path / "private_key.pem.b64").open("w", encoding ="utf-8") as file:
        file.write(base64.b64encode(private_pem).decode('utf-8'))

    with (path / "public_key.pem").open("w", encoding ="utf-8") as file:
        file.write(public_pem.decode('utf-8'))

    with (path / "public_key.xml").open("w", encoding ="utf-8") as file:
        file.write(public_key_xml)

    with (path / "public_key.xml.b64").open("w", encoding ="utf-8") as file:
        file.write(base64.b64encode(public_key_xml.encode('utf-8')).decode('utf-8'))


@app.command()
def test_rsa(path: Annotated[Optional[Path], typer.Option()] = None):
    if path is None:
        path = Path('.')
    if path.is_file():
        print("Path must be a directory, but is a file.")
        raise typer.Abort()
    elif path.is_dir():
        pass
    elif not path.exists():
        print("Path does not exist.")
        raise typer.Abort()
    
    if not ((path / "private_key.pem").is_file()
            and (path / "private_key.pem.b64").is_file()
            and (path / "public_key.pem").is_file()
            and (path / "public_key.xml").is_file()
            and (path / "public_key.xml.b64").is_file()):
        print("RSA key files missing.")
        raise typer.Abort()

    with (path / "private_key.pem").open("r", encoding ="utf-8") as file:
        private_pem = file.read().encode('utf-8')

    with (path / "public_key.pem").open("r", encoding ="utf-8") as file:
        public_pem = file.read().encode('utf-8')
    
    payload = {"test": "test"}

    try:
        token = jwt.encode(payload, private_pem, algorithm="RS256")
    except:
        print("PEM Test: Error in private_key.pem")
        raise typer.Abort()

    try:
        decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
        print('PEM Test: Ok')
    except jwt.ExpiredSignatureError:
        print("PEM Test: Signature has expired")
        raise typer.Abort()
    except jwt.InvalidTokenError:
        print("PEM Test: Invalid token")
        raise typer.Abort()
    except:
        print("PEM Test: Error")
        raise typer.Abort()
    
    with (path / "private_key.pem.b64").open("r", encoding ="utf-8") as file:
        private_pem = base64.b64decode(file.read().encode('utf-8'))
    
    try:
        token = jwt.encode(payload, private_pem, algorithm="RS256")
    except:
        print("Base64 Test: Error in private_key.pem.b64")
        raise typer.Abort()

    try:
        decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
        print('Base64 Test: Ok')
    except jwt.ExpiredSignatureError:
        print("Base64 Test: Signature has expired")
        raise typer.Abort()
    except jwt.InvalidTokenError:
        print("PBase64EM Test: Invalid token")
        raise typer.Abort()
    except:
        print("Base64 Test: Error")
        raise typer.Abort()