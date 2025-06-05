    /* https://www.w3.org/TR/webauthn-3/#sctn-sample-scenarios */
    function registerPasskey(challenge,passkeyName, rpName, userName, email ) {
        console.log("in registerPasskey " + name);
        if(!challenge) {
            console.log("no name for challenge provided.");
            throw new Error("no name for challenge provided.");
        }
        if(!passkeyName) {
            console.log("no name for passeky provided. Passkey has to have a name.");
            throw new Error("no name for passeky provided. Passkey has to have a name.");
        }

        if (!window.PublicKeyCredential) { /* Client not capable. Handle error. */
            throw new Error("this browser is not capable for passkeys");
        }

        var publicKeyConfiguration = {
          // The challenge is produced by the server; see the Security Considerations
          challenge: Uint8Array.from(challenge, c=>c.charCodeAt(0)),

          // Relying Party:
          rp: {
            name: rpName
          },

          // User:
          user: {
            id: Uint8Array.from(email, c=>c.charCodeAt(0)),
            name: email,
            displayName: userName,
          },

          // This Relying Party will accept either an ES256 or RS256 credential, but
          // prefers an ES256 credential.
          pubKeyCredParams: [
            {
              type: "public-key",
              alg: -7 // "ES256" as registered in the IANA COSE Algorithms registry
            },
            {
              type: "public-key",
              alg: -257 // Value registered by this specification for "RS256"
            }
          ],

          authenticatorSelection: {
            // Try to use UV if possible. This is also the default.
            userVerification: "preferred"
          },

          timeout: 300000,  // 5 minutes
          //excludeCredentials: [
          //  // Don't re-register any authenticator that has one of these credentials
          //  // examples:
          //  {"id": Uint8Array.from(window.atob("ufJWp8YGlibm1Kd9XQBWN1WAw2jy5In2Xhon9HAqcXE="), c=>c.charCodeAt(0)), "type": "public-key"},
          //  {"id": Uint8Array.from(window.atob("E/e1dhZc++mIsz4f9hb6NifAzJpF1V4mEtRlIPBiWdY="), c=>c.charCodeAt(0)), "type": "public-key"}
          //],

          // Make excludeCredentials check backwards compatible with credentials registered with U2F
          //extensions: {"appidExclude": "https://acme.example.com"}
        };

        // Note: The following call will cause the authenticator to display UI.
        return navigator.credentials.create({publicKey: publicKeyConfiguration })

    }

    function addError(err) {
        const li = document.createElement("li");
        li.appendChild(document.createTextNode(err));
        errorList.appendChild(li);
        if(errors.hasAttribute("hidden")) {
            errors.removeAttribute("hidden");
        }
    }

    function clearAndHideErrors() {
        while(errorList && errorList.children && errorList.children.length > 0) {
            errorList.removeChild(errorList.firstChild);
        }
        errors.setAttribute("hidden", true);
    }



