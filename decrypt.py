"""
Decode in Python a string encoded in Laravel 6.x
String ENCODED in Laravel 6.x with default pakage
Illuminate\Support\Facades\Crypt
and command like:
$encrypted = Crypt::encrypt('Hello world.');
Test in 
php artisan tinker
>>use Illuminate\Support\Facades\Crypt;
>>$encrypted = Crypt::encrypt('Hello world.');
Strings DECODED in Python 3.7 (64bit) with just following requirements:
phpserialize==1.3
pycryptodome==3.9.7
NOTE: avoid using in Laravel
$encrypted = Crypt::encryptString('Hello world.');
as this does NOT serializes strings :  not-serialized strings are not handled by this script.
"""
import os
import base64
import json
from Crypto.Cipher import AES
from phpserialize import loads


def decrypt(laravelEncrypedStringBase64, laravelAppKeyBase64):
    # Decode from base64 Laravel encrypted string
    dataJson = base64.b64decode(laravelEncrypedStringBase64)
    # Load JSON
    data = json.loads(dataJson)
    # Extract actual encrypted message from JSON (other parts are IV and Signature)
    value =  base64.b64decode(data['value'])
    # Extract Initialization Vector from JSON (required to create an AES decypher)
    iv = base64.b64decode(data['iv'])
    # Decode 
    key = base64.b64decode(laravelAppKeyBase64)  # Laravel KEY comes base64Encoded from .env!
    # Create an AES decypher
    decrypter = aesDecrypterCBC(iv, key)
    # Finally decypher the message
    decriptedSerializedMessage = decrypter.decrypt(value)
    # deserialize message
    try :
        # Attempt to deserialize message incase it was created in Laravel with Crypt::encrypt('Hello world.');
        decriptedMessage = unserialize(decriptedSerializedMessage)
        return str(decriptedMessage)
    except:
        raise Exception("Check you cyphered strings in Laravel using Crypt::encrypt() and NOT Crypt::encryptString()")

def aesDecrypterCBC(iv, _key):
    decrypterAES_CBC = AES.new(key=_key,mode=AES.MODE_CBC,IV=iv)
    return decrypterAES_CBC

def unserialize(serialized):
    return loads(serialized)
    
if __name__ == "__main__":
    
    laravelAppKeyBase64 = b"tZMp17lQI70EEYqCsQfwLzlHm6tyaYWPAX66n7YA8KI="
    # Following string is obtained with: $encrypted = Crypt::encrypt('Hello world.');
    laravelEncrypedString = b"eyJpdiI6ImZTQnQ0VEF1NkdWVXdneXRjXC85RjdBPT0iLCJ2YWx1ZSI6IlIxcjhkNDVOZFV3djZLMVVmK0RZQkFYTjBOelpxMEtEYmRRdlBlbHhIcnM9IiwibWFjIjoiNzk3NzI2NTQyOGZkYWRlN2NjZjBiYTUxNWI0YWJlOGU0YjI4MDg2YzI3ZDRlNmMzZTQwOTk3ZTI0YmI2ZTBmYiJ9"
    # Following string is obtained with: $encrypted = Crypt::encryptString('Hello world.'); WILL NOT WORK!!
    #laravelEncrypedString = b"eyJpdiI6Iko0aWpwNFdKU0g2WE95TFlWY2dHaFE9PSIsInZhbHVlIjoiRTFtTG14eTZQbTMrVzZxS0R6OFBEZz09IiwibWFjIjoiYzhhN2VlNThmNDczNGM2M2M5ZDJiNzQ4ZjEzM2MxMDg2M2FmMzFmZTgwNjE3NDYyOWEzYzU1NTNmMmU2OWRjYSJ9"
    decrypted = decrypt(laravelEncrypedString, laravelAppKeyBase64)
    print(decrypted)
