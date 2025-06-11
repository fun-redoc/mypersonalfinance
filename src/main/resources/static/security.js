function generateKey(size) {
    return key = window.crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt'])
    /*
    .then(key => {
      encryptionKey = key;
    }).catch(err => {
      console.error(err);
    });
    */
}


// Funktion zum Verschlüsseln von Text
function encryptData() {
  const iv = window.crypto.getRandomValues(new Uint8Array(size)); // initialization vector
  let encoder = new TextEncoder();
  let dataToEncrypt = encoder.encode('Secure Text');

  window.crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, encryptionKey, dataToEncrypt).then(cipherText => {
    let encryptedData = new Uint8Array(cipherText);
    console.log(`Chiffriertext: ${Array.from(encryptedData).join(",")}`); // Anzeigen der verschlüsselten Daten
  }).catch(err => {
    console.error(err);
  });
}

// Funktion zum Entschlüsseln von Text
function decryptData() {
  let encryptedData = new Uint8Array([/*Hier kommen die Chiffrierdaten hin*/]); // Fügen Sie die verschlüsselten Daten hinzu

  window.crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, encryptionKey, encryptedData.buffer).then(plainText => {
    let decoder = new TextDecoder();
    console.log(`Klartext: ${decoder.decode(plainText)}`);  // Anzeigen der entschlüsselten Daten
  }).catch(err => {
    console.error(err);
  });
}


function AES() {

  let aes = {};

  aes.encrypt = async (message, password, passwordBits, iterations) => {

    let rounds = iterations || 500000;
    let msg = new TextEncoder().encode(message);
    let pass;

    if (password) {
      pass = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }

    if (passwordBits) {
      pass = await crypto.subtle.importKey('raw',new Uint8Array(passwordBits),{
        "name": "PBKDF2"
      },false,['deriveBits'])
    }

    let salt = crypto.getRandomValues(new Uint8Array(32));
    let iv = crypto.getRandomValues(new Uint8Array(12));

    let bits = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": rounds,
      "hash": {
        "name": "SHA-256"
      }
    }, pass, 256);

    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['encrypt']);

    let enc = await crypto.subtle.encrypt({
      "name": "AES-GCM",
      "iv": iv
    }, key, msg);

    let iterationsHash = btoa(rounds.toString());

    let saltHash = btoa(Array.from(new Uint8Array(salt)).map(val => {
      return String.fromCharCode(val)
    }).join(''));

    let ivHash = btoa(Array.from(new Uint8Array(iv)).map(val => {
      return String.fromCharCode(val)
    }).join(''));

    let encHash = btoa(Array.from(new Uint8Array(enc)).map(val => {
      return String.fromCharCode(val)
    }).join(''));

    return iterationsHash + '.' + saltHash + '.' + ivHash + '.' + encHash;

  };

  aes.decrypt = async (encrypted, password, passwordBits) => {

    let parts = encrypted.split('.');
    let rounds = parseInt(atob(parts[0]));

    let salt = new Uint8Array(atob(parts[1]).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let iv = new Uint8Array(atob(parts[2]).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let enc = new Uint8Array(atob(parts[3]).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let pass;

    if (password) {
      pass = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }

    if (passwordBits) {
      pass = await crypto.subtle.importKey('raw', new Uint8Array(passwordBits), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }

    let bits = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": rounds,
      "hash": {
        "name": "SHA-256"
      }
    }, pass, 256);

    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['decrypt']);

    let dec = await crypto.subtle.decrypt({
      "name": "AES-GCM",
      "iv": iv
    }, key, enc);

    return (new TextDecoder().decode(dec));

  };

  return aes;

}
