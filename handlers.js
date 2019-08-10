const radius = require('radius');
const chap = require('chap');
const crypto = require('crypto');

const MicrosoftVendorID = 311;
const ChallengeKey = 11;
const NtResponseKey = 1;
const NtResponse2Key = 25;

class AuthHandler {

    constructor(packet, secret, username, cPassword) {
        this.packet = packet;
        this.secret = secret;
        this.username = username;
        this.cPassword = cPassword;
    }

    authable() {
        return false;
    }

    check() {
        return false;
    }

    success(vendorAttrs) {
        let attributes = [
            ['Reply-Message', 'Hi, ' + this.username],
        ];
        if (vendorAttrs) {
            attributes.push(vendorAttrs);
        }
        return {
            packet: this.packet,
            code: 'Access-Accept',
            secret: this.secret,
            attributes,
        };
    }

    failed() {
        return {
            packet: this.packet,
            code: 'Access-Reject',
            secret: this.secret,
            attributes: [
                ['Reply-Message', 'Invalid password'],
            ]
        };
    }
}

class PapAuthHandler extends AuthHandler {
    authable() {
        return typeof this.packet.attributes['User-Password'] !== 'undefined';
    }

    check() {
        if (this.packet.attributes['User-Password'] === this.cPassword) {
            return this.success();
        } else {
            return this.failed();
        }
    }
}

class ChapAuthHandler extends AuthHandler {
    authable() {
        return typeof this.packet.attributes['CHAP-Password'] !== 'undefined';
    }

    check() {
        let hash = this.packet.attributes['CHAP-Password'];
        let challenge = this.packet.authenticator;

        if (ChapAuthHandler.chapMatch(this.cPassword, hash, challenge)) {
            return this.success();
        } else {
            return this.failed();
        }
    }

    static chapMatch(cPassword, chapPassword, challenge) {
        let hash = chapPassword.slice(1);
        let md5 = crypto.createHash('md5');
        md5.write(chapPassword.slice(0, 1));
        md5.write(Buffer.from(cPassword));
        md5.write(challenge);
        let calc = md5.digest('hex');

        return hash.equals(Buffer.from(calc, 'hex'));
    }
}

class MSChapAuthHandler extends AuthHandler {

    authable() {
        this.extractMicroSoftAttrs();
        if (Object.keys(this.msAttrs).length === 2) {
            this.challenge = MSChapAuthHandler.decodeChallenge(this.msAttrs[ChallengeKey]).value;
            return true;
        } else {
            return false;
        }
    }

    extractMicroSoftAttrs() {
        let rawAttrs = this.packet.raw_attributes;
        let msAttrs = {};
        for (let i in rawAttrs) {
            try {
                if (rawAttrs[i][1].readUIntBE(0, 4) === MicrosoftVendorID) {
                    msAttrs[rawAttrs[i][1].readUIntBE(4, 1)] = rawAttrs[i][1];
                }
            } catch (e) {
                //
            }
        }
        this.msAttrs = msAttrs;
    }

    static decodeChallenge(buf) {
        return {
            vendorId: buf.readUIntBE(0, 4),
            vendorType: buf.readUIntBE(4, 1),
            vendorLength: buf.readUIntBE(5, 1),
            value: buf.slice(6),
        };
    }

    static hashNtPasswordHash(passwordHash) {
        let md4 = crypto.createHash('md4');
        md4.update(passwordHash);
        return md4.digest('hex');
    }
}

class MSChapV1AuthHandler extends MSChapAuthHandler {
    authable() {
        if (super.authable()) {
            return typeof this.msAttrs[NtResponseKey] !== 'undefined';
        } else {
            return false;
        }
    }

    check() {
        const res = MSChapV1AuthHandler.decodeResponse(this.msAttrs[NtResponseKey]);
        if (res.flags !== 0) {
            if (res.lmResponse.equals(Buffer.from(new Array(24).fill(0)))) {
                const calc = MSChapV1AuthHandler.encryptv1(this.challenge, this.cPassword);
                const mppe = MSChapV1AuthHandler.mppev1(this.cPassword);

                if (calc.equals(res.response)) {
                    return this.success(
                        ['Vendor-Specific', MicrosoftVendorID, [
                            [7, Buffer.from([0x0, 0x0, 0x0, 0x01])],
                            [8, Buffer.from([0x0, 0x0, 0x0, 0x06])],
                            [12, mppe],
                        ]]
                    );
                } else {
                    return this.failed();
                }
            } else {
                return this.failed();
            }
        } else {
            return this.failed();
        }
    }

    static decodeResponse(buf) {
        return {
            vendorId: buf.readUIntBE(0, 4),
            vendorType: buf.readUIntBE(4, 1),
            vendorLength: buf.readUIntBE(5, 1),
            ident: buf.readUIntBE(6, 1),
            flags: buf.readUIntBE(7, 1),
            lmResponse: buf.slice(8, 32),
            response: buf.slice(32),
        };
    }

    static encryptv1(challenge, password) {
        return chap.MSCHAPv1.NtChallengeResponse(challenge, password);
    }

    static mppev1(password) {

        let res = Buffer.alloc(0);
        let passwordHash = chap.MSCHAPv1.NtPasswordHash(password);

        let lm = chap.MSCHAPv1.LmPasswordHash(password);
        lm = lm.slice(0, 8);

        res = Buffer.concat([res, lm]);
        let hashHash = MSChapAuthHandler.hashNtPasswordHash(passwordHash);
        res = Buffer.concat([res, Buffer.from(hashHash, 'hex').slice(0, 16)]);
        res = Buffer.concat([res, Buffer.from(new Array(8).fill(0))]);

        return res;
    }
}

class MSChapV2AuthHandler extends MSChapAuthHandler {
    authable() {
        if (super.authable()) {
            return typeof this.msAttrs[NtResponse2Key] !== 'undefined';
        } else {
            return false;
        }
    }

    check() {
        const res = MSChapV2AuthHandler.decodeResponse2(this.msAttrs[NtResponse2Key]);
        if (res.flags === 0) {
            const enc = chap.MSCHAPv2.GenerateNTResponse(this.challenge, res.peerChallenge, this.username, this.cPassword);
            const authenticatorResponse = chap.MSCHAPv2.GenerateAuthenticatorResponse(
                this.cPassword, enc, res.peerChallenge, this.challenge, this.username
            );
            if (enc.equals(res.response)) {
                const code = 'Access-Accept';
                const [sendEnc, recvEnc] = MSChapV2AuthHandler.mmpev2(this.secret, this.cPassword, this.packet.authenticator, res.response);

                if (sendEnc && recvEnc) {

                    return this.success(
                        ['Vendor-Specific', MicrosoftVendorID, [
                            [7, Buffer.from([0x0, 0x0, 0x0, 0x01])],
                            [8, Buffer.from([0x0, 0x0, 0x0, 0x06])],
                            [26, Buffer.concat([Buffer.from([res.ident]), Buffer.from(authenticatorResponse)])],
                            [16, sendEnc],
                            [17, recvEnc],
                        ]]
                    );
                } else {
                    return this.failed();
                }
            } else {
                return this.failed();
            }
        } else {
            return this.failed();
        }
    }

    static decodeResponse2(buf) {
        return {
            vendorId: buf.readUIntBE(0, 4),
            vendorType: buf.readUIntBE(4, 1),
            vendorLength: buf.readUIntBE(5, 1),
            ident: buf.readUIntBE(6, 1),
            flags: buf.readUIntBE(7, 1),
            peerChallenge: buf.slice(8, 24),
            response: buf.slice(32),
        };
    }

    static createMD5(bufArray) {
        let md5 = crypto.createHash('md5');
        for (let i in bufArray) {
            md5.write(bufArray[i]);
        }
        return md5.digest('hex');
    }

    static masterKeys(password, ntResponse) {
        let hashHash = MSChapAuthHandler.hashNtPasswordHash(chap.MSCHAPv2.NtPasswordHash(password));
        let masterKey = chap.MSCHAPv2.GetMasterKey(Buffer.from(hashHash, 'hex'), ntResponse);

        let sendKey = chap.MSCHAPv2.GetAsymmetricStartKey(masterKey, 16, true, true);
        let recvKey = chap.MSCHAPv2.GetAsymmetricStartKey(masterKey, 16, false, true);

        return [sendKey, recvKey];
    }

    static xor(a, b) {
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
    }

    static multipleOf(data, size) {
        if (data.length % size !== 0) {
            data = Buffer.concat([data, Buffer.alloc(size - (data.length % size))]);
        }
        return data;
    }

    static salt(offset) {
        const maxNum = 4294967296, minNum = 0;
        let salt = parseInt(Math.random() * (maxNum - minNum + 1) + minNum, 10);
        return Buffer.from([0x80 | ((offset & 0x0f) << 3) | (salt & 0x07), salt]);
    }

    static tunnelPass(secret, key, authenticator, salt) {
        let P = Buffer.concat([Buffer.alloc(key.length), key]);
        P = MSChapV2AuthHandler.multipleOf(P, 16);

        let b = [], c = [], C = Buffer.alloc(0);

        for (let i = 0; i < P.length / 16; i++) {
            let p = P.slice(i * 16, (i + 1) * 16);
            if (i === 0) {
                b.push(Buffer.from(MSChapV2AuthHandler.createMD5([Buffer.from(secret), authenticator, salt]), 'hex'));
                c.push(MSChapV2AuthHandler.xor(p, b[i]));
                C = c[i];
            } else {
                b.push(Buffer.from(MSChapV2AuthHandler.createMD5([Buffer.from(secret), c[i-1]]), 'hex'));
                c.push(MSChapV2AuthHandler.xor(p, b[i]));
                C = Buffer.concat([C, c[i]]);
            }
        }

        if (C.length % 16 !== 0) {
            return false;
        }

        let plain = Buffer.from([salt[0], salt[1]]);
        plain = Buffer.concat([plain, C]);
        return plain;
    }

    static mmpev2(secret, password, authenticator, ntResponse) {
        let [sendKey, recvKey] = MSChapV2AuthHandler.masterKeys(password, ntResponse);

        let sendEnc = MSChapV2AuthHandler.tunnelPass(secret, sendKey, authenticator, MSChapV2AuthHandler.salt(0));
        let recvEnc = MSChapV2AuthHandler.tunnelPass(secret, recvKey, authenticator, MSChapV2AuthHandler.salt(1));

        return [sendEnc, recvEnc];
    }
}

module.exports = {
    PapAuthHandler,
    ChapAuthHandler,
    MSChapV1AuthHandler,
    MSChapV2AuthHandler,
};