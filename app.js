const radius = require('radius');
const chap = require('chap');
const mschap = require('./mschap');
const crypto = require('crypto');
const dgram = require('dgram');

const secret = 'secret';
const authServer = dgram.createSocket('udp4');
const acctServer = dgram.createSocket('udp4');

authServer.on('message', (msg, req) => {
    let packet = radius.decode({packet: msg, secret});
    if (packet.code === 'Access-Request') {

        const cPassword = 'a111111';

        let username = packet.attributes['User-Name'];
        let password = packet.attributes['User-password'];

        if (typeof password !== 'undefined') {

        } else {
            // check mschap
            const MicrosoftID = 311;
            let rawAttrs = packet.raw_attributes;
            let msAttrs = {};
            for (let i in rawAttrs) {
                if (rawAttrs[i][1].readUIntBE(0, 4) === MicrosoftID) {
                    msAttrs[packet.raw_attributes[i][1].readUIntBE(4, 1)] = rawAttrs[i][1];
                }
            }

            if (Object.keys(msAttrs).length === 2) {
                const challengeKey = 11;
                const ntResponseKey = 1;
                const ntResponse2Key = 25;

                let challenge = mschap.decodeChallenge(msAttrs[challengeKey]).value;
                if (msAttrs[ntResponseKey]) {
                    // mschap v1
                } else if (msAttrs[ntResponse2Key]) {
                    // mschap v2
                    let res = mschap.decodeResponse2(msAttrs[ntResponse2Key]);
                    if (res.flags === 0) {
                        let enc = chap.MSCHAPv2.GenerateNTResponse(challenge, res.peerChallenge, username, cPassword);
                        let authenticatorResponse = chap.MSCHAPv2.GenerateAuthenticatorResponse(cPassword, enc, res.peerChallenge, challenge, username);

                        if (enc.equals(res.response)) {
                            let code = 'Access-Accept';
                            let [sendEnc, recvEnc] = mschap.mmpev2(secret, cPassword, packet.authenticator, res.response);
                            let msResponse = radius.encode_response({
                                packet: packet,
                                code: code,
                                secret: secret,
                                attributes: [
                                    ['Vendor-Specific', MicrosoftID, [
                                        [7, Buffer.from([0x0, 0x0, 0x0, 0x01])],
                                        [8, Buffer.from([0x0, 0x0, 0x0, 0x06])],
                                        [26, Buffer.concat([Buffer.from([res.ident]), Buffer.from(authenticatorResponse)])],
                                        [16, sendEnc],
                                        [17, recvEnc],
                                    ]],
                                    ['Framed-IP-Address', '192.168.43.5'],
                                    ['Reply-Message', 'Hi, gaolool'],
                                    ['Session-Timeout', 0], //0 is unlimited
                                    // ['Accend-Data-Rate', Buffer.from('128k')], //upload
                                    // ['Accend-Xmit-Rate', Buffer.from('128k')], //download
                                    // ['Rate-Limit', Buffer.from('128k')]
                                ]
                            });
                            console.log('Sending ' + code + ' for user ' + username);
                            authServer.send(msResponse, 0, msResponse.length, req.port, req.address, (err, bytes) => {
                                if (err) {
                                    console.log('Error sending response to ', req);
                                }
                            });
                        } else {
                            // failed
                        }
                    } else {
                        // failed
                    }
                }
            }
        }

    } else {
        console.log('Unknown packet type: ', packet.code);
    }
});

authServer.on("listening", function () {
    let address = authServer.address();
    console.log("radius authenticating server listening " +
        address.address + ":" + address.port);
});
authServer.bind(1812);

acctServer.on("message", function (msg, rinfo) {

    console.log('acct: ', msg);authcating
    let code, username, password, packet;
    packet = radius.decode({packet: msg, secret: secret});

    console.log('acct: ', packet.code);
});



acctServer.on("listening", function () {
    let address = acctServer.address();
    console.log("radius accounting server listening " +
        address.address + ":" + address.port);
});

acctServer.bind(1813);