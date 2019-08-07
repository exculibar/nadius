const chap = require('chap');
const crypto = require('crypto');

module.exports = {
    decodeChallenge(buf) {
        return {
            vendorId: buf.readUIntBE(0, 4),
            vendorType: buf.readUIntBE(4, 1),
            vendorLength: buf.readUIntBE(5, 1),
            value: buf.slice(6),
        };
    },

    decodeResponse2(buf) {
        return {
            vendorId: buf.readUIntBE(0, 4),
            vendorType: buf.readUIntBE(4, 1),
            vendorLength: buf.readUIntBE(5, 1),
            ident: buf.readUIntBE(6, 1),
            flags: buf.readUIntBE(7, 1),
            peerChallenge: buf.slice(8, 24),
            response: buf.slice(32),
        };
    },

    createMD5(bufArrary) {
        let md5 = crypto.createHash('md5');
        for (let i in bufArrary) {
            md5.write(bufArrary[i]);
        }
        return md5.digest('hex');
    },

    hashNtPasswordHash(passwordHash) {
        let md4 = crypto.createHash('md4');
        md4.update(passwordHash);
        return md4.digest('hex');
    },

    masterKeys(password, ntResponse) {
        let hashHash = this.hashNtPasswordHash(chap.MSCHAPv2.NtPasswordHash(password));
        let masterKey = chap.MSCHAPv2.GetMasterKey(Buffer.from(hashHash, 'hex'), ntResponse);

        let sendKey = chap.MSCHAPv2.GetAsymmetricStartKey(masterKey, 16, true, true);
        let recvKey = chap.MSCHAPv2.GetAsymmetricStartKey(masterKey, 16, false, true);

        return [sendKey, recvKey];
    },

    xor(a, b) {
        if (a.length !== b.length) {
            return false;
        } else {
            let n = a.length;
            let out = Buffer.alloc(n);
            for (let i = 0; i < n; i += 1) {
                out[i] = a[i] ^ b[i];
            }
            return out;
        }
    },

    multipleOf(data, size) {
        if (data.length % size !== 0) {
            data = Buffer.concat([data, Buffer.alloc(size - (data.length % size))]);
        }
        return data;
    },

    salt(offset) {
        const maxNum = 4294967296, minNum = 0;
        let salt = parseInt(Math.random() * (maxNum - minNum + 1) + minNum, 10);
        return Buffer.from([0x80 | ((offset & 0x0f) << 3) | (salt & 0x07), salt]);
    },

    tunnelPass(secret, key, authenticator, salt) {
        let P = Buffer.concat([Buffer.alloc(key.length), key]);
        P = multipleOf(P, 16);

        let b = [], c = [], C = null;

        for (let i = 0; i < P.length / 16; i++) {
            let p = P.slice(i * 16, (i + 1) * 16);
            if (i === 0) {
                b.push(Buffer.from(createMD5([Buffer.from(secret), authenticator, salt]), 'hex'));
                c.push(xor(p, b[i]));
                C = c[i];
            } else {
                b.push(Buffer.from(createMD5([Buffer.from(secret), c[i-1]]), 'hex'));
                c.push(xor(p, b[i]));
                C = Buffer.concat([C, c[i]]);
            }
        }

        if (C.length % 16 !== 0) {
            return false;
        }

        let plain = Buffer.from([salt[0], salt[1]]);
        plain = Buffer.concat([plain, C]);
        return plain;
    },

    mmpev2(secret, password, authenticator, ntResponse) {
        let [sendKey, recvKey] = masterKeys(password, ntResponse);

        let sendEnc = tunnelPass(secret, sendKey, authenticator, salt(0));
        let recvEnc = tunnelPass(secret, recvKey, authenticator, salt(1));

        return [sendEnc, recvEnc];
    },
};