function hexToBytes(hex) {
  var bytes = new Uint8Array(hex.length / 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(2 * i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] < 16) {
      out += '0';
    }
    out += bytes[i].toString(16);
  }
  return out;
}

// This function assumes |str| is ascii - i.e. no char codes > 255.
function stringToBytes(str) {
  var bytes = new Uint8Array(str.length);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

function base64ToBytes(base64) {
  return stringToBytes(atob(base64));
}

function bytesToBase64(bytes) {
  return btoa(bytes.reduce(function(acc, b) {
    return acc + String.fromCharCode(b);
  }, ''));
}

function xor(b1, b2) {
  var bytes = new Uint8Array(b1.length);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = b1[i] ^ b2[i];
  }
  return bytes;
}

function truncateUint8Array(data, newLen) {
  return data.slice(0, newLen);
}

function concatUint8Array(b1, b2) {
  var ret = new Uint8Array(b1.length + b2.length);
  ret.set(b1);
  ret.set(b2, b1.length);
  return ret;
}

function padding(len) {
  var bytes = new Uint8Array(len);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = len;
  }
  return bytes;
}

function CbcPaddingOracle(onConstruction) {
  var alg = {name: "AES-CBC", length: 128};
  window.crypto.subtle.generateKey(alg, false, ['encrypt', 'decrypt']).then(function(key) {
    this.key_ = key;
    if (onConstruction != null) {
      onConstruction();
    }
  }.bind(this));

  this.encrypt = function(plaintext) {
    var iv = new Uint8Array(16);
    window.crypto.getRandomValues(iv);
    var alg = {name: "AES-CBC", length: 128, iv: iv};
    return window.crypto.subtle.encrypt(alg, this.key_, plaintext).then(function(ciphertext) {
      return [iv, new Uint8Array(ciphertext)];
    });
  };

  this.hasValidPadding = function(iv, ciphertext) {
    var alg = {name: "AES-CBC", length: 128, iv: iv};
    // console.log('iv:', bytesToHex(iv), 'ct:', bytesToHex(ciphertext));
    return window.crypto.subtle.decrypt(alg, this.key_, ciphertext).then(
      function() { return true; },
      function() { return false; }
    );
  };
}

function generateECBKey() {
  var alg = {name: "AES-CBC", length: 128};
  return window.crypto.subtle.generateKey(alg, false, ['encrypt', 'decrypt']);
}

function encryptECB(key, plaintext) {
  var iv = new Uint8Array(16);
  var alg = {name: "AES-CBC", length: 128, iv: iv};
  
  var ciphertext = new Uint8Array(plaintext.length);
  function encryptBlock(offset, block) {
    return window.crypto.subtle.encrypt(alg, key, block)
    .then(function(ctBlock) {
      ciphertext.set(ctBlock.slice(0, 16), offset);
    });
  }

  var chain = Promise.resolve();
  for (var i = 0; i < plaintext.length; i += 16) {
    var block = plaintext.slice(i, i + 16);
    chain = chain.then(function() {
      return encryptBlock(i, block);
    });
  }
  return chain.then(function() { return ciphertext; });
}

function decryptECB(key, ciphertext) {
  var iv = new Uint8Array(16);
  var alg = {name: "AES-CBC", length: 128, iv: iv};

  function decryptBlock(partialPt, block, guess) {
    guess = guess || 0;
    var expandedCt = new Uint8Array(16*3);
    expandedCt.set(block);
    expandedCt[31] = guess;
    return window.crypto.subtle.decrypt(alg, key, expandedCt)
    .then(function(pt) {
      var pt = truncateUint8Array(new Uint8Array(pt), 16);
      return concatUint8Array(partialPt, pt);
    },
    function() {
      if (guess < 255) {
        return decryptBlock(partialPt, block, guess + 1);
      } else {
        throw new Error("Failed ECB decryption");
      }
    });
  }

  var chain = Promise.resolve(new Uint8Array(0));
  for (var i = 0; i < ciphertext.length; i += 16) {
    var block = ciphertext.slice(i, i + 16);
    chain = chain.then(function(partialPt) {
      return decryptBlock(partialPt, block);
    });
  }
  return chain;
}

/* Demo code using ECB functions
var key;
generateECBKey().then(function(k) {
  key = k;
  console.log(key);
  var b = hexToBytes("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
  return encryptECB(key, b);
}).then(function(ct) {
  console.log(ct);
  console.log(bytesToHex(ct));
  return decryptECB(key, ct);
}).then(function(pt) {
  console.log(pt);
  console.log(bytesToHex(pt));
});
*/

// |iv| and |ciphertext| are Uint8Arrays, |oracle| is a function that takes two
// arguments iv and ciphertext, and returns a promise that resolves to true or
// false. This function returns a promise that resolves to the length of the
// padding.
function findPaddingLength(iv, ciphertext, oracle) {
  function try_len(potential_len) {
    var newIv = iv;
    var newCt = ciphertext;
    if (ciphertext.length == 16) {
      var xorBytes = new Uint8Array(16);
      xorBytes[16 - potential_len - 1] = 1;
      newIv = xor(iv, xorBytes);
    } else {
      var xorBytes = new Uint8Array(ciphertext.length);
      xorBytes[ciphertext.length - 16 - potential_len - 1] = 1;
      newCt = xor(ciphertext, xorBytes);
    }
    return oracle(newIv, newCt).then(function(success) {
      if (success) {
        return potential_len;
      } else if (potential_len == 15) {
        return 16;
      }
      return try_len(potential_len + 1);
    });
  }
  return try_len(1);
}

function findNextByte(iv, ciphertext, oracle, decodedBytes) {
  console.log(decodedBytes.length, ciphertext.length);
  if (decodedBytes.length == ciphertext.length) {
    var e = new Uint8Array();
    return Promise.resolve([decodedBytes, e, e, e, true]);
  }
  var shortenedCt = ciphertext;
  var shortenedPt = decodedBytes; // Will be length 0-15.
  if (decodedBytes.length >= 16) {
    var extraBlocks = Math.floor(decodedBytes.length / 16);
    shortenedCt = truncateUint8Array(ciphertext, ciphertext.length - 16 * extraBlocks);
    shortenedPt = truncateUint8Array(decodedBytes, decodedBytes.length - 16 * extraBlocks);
  }
  // |b| is the guess as to what the next plaintext byte is.
  var newIv = iv;
  function tryByte(b) {
    var xorBlocks = new Uint8Array(shortenedCt.length);
    var padding = 1 + shortenedPt.length;
    var skipBlocks = shortenedCt.length / 16 - 1;
    if (shortenedCt.length == 16) {
      skipBlocks = 1;
    }
    xorBlocks[16 * skipBlocks - shortenedPt.length - 1] = b ^ padding;
    for (var i = 0; i < shortenedPt.length; i++) {
      xorBlocks[16 * skipBlocks - shortenedPt.length + i] = shortenedPt[i] ^ padding;
    }
    var iv = newIv;
    var ct = shortenedCt;
    if (shortenedCt.length == 16) {
      iv = xor(iv, xorBlocks);
    } else {
      ct = xor(ct, xorBlocks);
    }
    return oracle(iv, ct).then(function(success) {
      if (success) {
        var newPt = new Uint8Array(decodedBytes.length + 1);
        newPt[0] = b;
        for (var i = 1; i < newPt.length; i++) {
          newPt[i] = decodedBytes[i-1];
        }
        return [newPt, iv, ct, xorBlocks, shortenedCt.length == 16];
      }
      if (b < 255) {
        return tryByte(b + 1);
      }
      throw new Error("Found no acceptable byte");
    });
  }
  return tryByte(0);
}

window.addEventListener('load', function() {
  configureSlideTransitions();
  configurePaddingDemo();
  configureBitFlipDemo();
  configurePaddingOracleDemo();
});

function padPlaintext(pt) {
  var len = 16 - (pt.length % 16);
  var padded = new Uint8Array(len + pt.length);
  for (var i = 0; i < pt.length; i++) {
    padded[i] = pt[i];
  }
  for (var i = 0; i < len; i++) {
    padded[pt.length + i] = len;
  }
  return padded;
}

function setHexValue(domId, hex, boldMask, maskBlockOffset) {
  maskBlockOffset = maskBlockOffset || 0;
  var node = document.getElementById(domId);
  node.innerHTML = '';
  if (hex instanceof Uint8Array) {
    hex = bytesToHex(hex);
  }
  for (var i = 0; i < hex.length; i += 32) {
    var s = document.createElement('code');
    s.classList.add('block');
    for (var j = 0; j < 32; j += 2) {
      var b = document.createElement('span');
      if (boldMask && (boldMask[(i + j)/2 - 16*maskBlockOffset] > 0)) {
        b.classList.add('bold');
      }
      if (hex[i + j] == '?') {
        b.classList.add('unknown');
      }
      b.innerText = hex.substr(i + j, 2);
      s.appendChild(b);
    }
    node.appendChild(s);
    node.appendChild(document.createElement('wbr'));
  }
}

function configureSlideTransitions() {
  var slides = document.querySelectorAll('.slide');
  var currentSlide = 0;
  function goToSlide(num) {
    if (num > currentSlide) {
      slides[currentSlide].classList.add('done');
      slides[currentSlide].classList.remove('visible');
      slides[num].classList.add('visible');
    } else {
      slides[currentSlide].classList.remove('visible');
      slides[num].classList.add('visible');
      slides[num].classList.remove('done');
    }
    for (var i = currentSlide + 1; i < num; i++) {
      slides[i].classList.add('done');
    }
    for (var i = num + 1; i < currentSlide; i++) {
      slides[i].classList.remove('done');
    }
    currentSlide = num;
    window.location.hash = num;
  }
  goToSlide(parseInt(window.location.hash.substr(1)) || 0);
  document.addEventListener('keydown', function(e) {
    // 37: left, 38: up, 39: right, 40: down
    if (e.keyCode == 40) {
      if (currentSlide + 1 < slides.length) {
        goToSlide(currentSlide + 1);
      } else {
        goToSlide(0);
      }
    }
    if (e.keyCode == 38) {
      if (currentSlide > 0) {
        goToSlide(currentSlide - 1);
      } else {
        goToSlide(slides.length - 1);
      }
    }
  });
}

function configurePaddingDemo() {
  function inputChanged(value) {
    var paddedPt = padPlaintext(stringToBytes(value));
    var plural = document.getElementById('padding-plural');
    if (paddedPt.length > 16) {
      plural.innerText = 'blocks are';
    } else {
      plural.innerText = 'block is';
    }
    setHexValue('padding-padded', paddedPt);  
  }
  var input = document.getElementById('padding-pt');
  input.addEventListener('input', function(e) {
    inputChanged(e.target.value);
  });
  inputChanged(input.value);
}

function configureBitFlipDemo() {
  var iv = new Uint8Array(16);
  window.crypto.getRandomValues(iv);
  var alg = {name: "AES-CBC", length: 128, iv: iv};
  var pt = stringToBytes('Hello Chrome Networking');
  var ct, key;
  window.crypto.subtle.generateKey(alg, false, ['encrypt', 'decrypt'])
    .then(function(k) {
      key = k;
      return window.crypto.subtle.encrypt(alg, key, pt);
    })
    .then(function(c) {
      ct = new Uint8Array(c);
      setHexValue('bitflipCT1', ct);
      setHexValue('bitflipPT1', padPlaintext(pt));
      var input = document.getElementById('bitflip-xor');
      function inputChanged(value) {
        value = hexToBytes(value);
        var ct2 = xor(ct, value);
        var pt2;
        window.crypto.subtle.decrypt(alg, key, ct2)
          .then(function(p) {
            pt2 = new Uint8Array(p);
            setHexValue('bitflipCT2', ct2, value, 0);
            setHexValue('bitflipPT2', padPlaintext(pt2), value, 1);
            setHexValue('bitflipCT1', ct, value, 0);
            setHexValue('bitflipPT1', padPlaintext(pt), value, 1);
          })
          .catch(function() {
            setHexValue('bitflipCT2', ct2, value, 0);
            setHexValue('bitflipCT1', ct, value, 0);
            setHexValue('bitflipPT2', "-".repeat(64));
            setHexValue('bitflipPT1', padPlaintext(pt));
          });
      };
      input.addEventListener('input', function(e) {
        inputChanged(e.target.value);
      });
      input.value = "0".repeat(32);
      input.style.width = (input.scrollWidth - 8) + 'px';
      inputChanged(input.value);
    });
}

function addQuestionMarks(pt, ct) {
  var res = "??".repeat(ct.length - pt.length) + bytesToHex(pt);
  return res;
}

function configurePaddingOracleDemo() {
  var iv, ciphertext, pt, len;
  function advance() {
    findNextByte(iv, ciphertext, c.hasValidPadding.bind(c), pt)
    .then(function(res) {
      pt = res[0];
      var iv = res[1];
      var ct = res[2];
      var xorBlocks = res[3];
      var lastBlock = res[4];
      if (lastBlock) {
        setHexValue('oracle-iv-xor', xorBlocks);
        setHexValue('oracle-ct-xor', new Uint8Array(0));
      } else {
        setHexValue('oracle-ct-xor', xorBlocks);
      }
      setHexValue('oracle-iv-trial', iv);
      setHexValue('oracle-ct-trial', ct);
      setHexValue('oracle-pt', addQuestionMarks(pt, ciphertext));
    });
  };
  var c = new CbcPaddingOracle(function() {
    c.encrypt(stringToBytes('Dinos are awesome!!!')).then(function(value) {
      iv = value[0];
      ciphertext = value[1];
      setHexValue('oracle-iv', iv);
      setHexValue('oracle-ct', ciphertext);
      return findPaddingLength(iv, ciphertext, c.hasValidPadding.bind(c));
    }).then(function(l) {
      len = l;
      pt = padding(len);
      setHexValue('oracle-pt', addQuestionMarks(pt, ciphertext));

      // We have the padding length - set up manual advancement.
      var advanceNode = document.getElementById('oracle-advance');
      advanceNode.addEventListener('click', advance);
      var resetNode = document.getElementById('oracle-reset');
      resetNode.addEventListener('click', function() {
        pt = padding(len);
        setHexValue('oracle-pt', addQuestionMarks(pt, ciphertext));
        setHexValue('oracle-iv-xor', '');
        setHexValue('oracle-ct-xor', '');
        setHexValue('oracle-iv-trial', '');
        setHexValue('oracle-ct-trial', '');
      });
    }).catch(function(e) {
      console.log('error:', e);
    });
  });
}
