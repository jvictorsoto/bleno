var debug = require('debug')('smp');

var events = require('events');
var util = require('util');

var crypto = require('./crypto');
var mgmt = require('./mgmt');

var SMP_CID = 0x0006;

var SMP_PAIRING_REQUEST = 0x01;
var SMP_PAIRING_RESPONSE = 0x02;
var SMP_PAIRING_CONFIRM = 0x03;
var SMP_PAIRING_RANDOM = 0x04;
var SMP_PAIRING_FAILED = 0x05;
var SMP_ENCRYPT_INFO = 0x06;
var SMP_MASTER_IDENT = 0x07;
var SMP_IDENT_INFO = 0x08;
var SMP_ADDR_INFO = 0x09;
var SMP_SIGN_INFO = 0x0A;
var SMP_SECURE_REQ = 0x0B;
var SMP_PAIRING_PUB_KEY = 0x0C;
var SMP_PAIRING_DHKEY_CHECK = 0x0D;
var SMP_PAIRING_KEYPRESS_NOT = 0x0E;

var SMP_BONDING_FLAG_NO_BONDING = 0x00;
var SMP_BONDING_FLAG_BONDING = 0x01;

var SMP_OOB_NO = 0x00;
var SMP_OOB_YES = 0x01;

var SMP_IO_DISPLAYONLY = 0x00;
var SMP_IO_DISPLAYYESNO = 0x01;
var SMP_IO_KEYBOARDONLY = 0x02;
var SMP_IO_NOINPUTNOOUTPUT = 0x03;
var SMP_IO_KEYBOARDDISPLAY = 0x04;

var SMP_AUTH_LEGACY = 0x00;
var SMP_AUTH_LESC = 0x01;

var SMP_MODEL_JUSTWORKS = 0x00;
var SMP_MODEL_PASSKEY = 0x01;
var SMP_MODEL_NUMERIC = 0x02;
var SMP_MODEL_OOB = 0x03;

var SMP_UNSPECIFIED = 0x08; // TODO: Remove

var Smp = function (aclStream, localAddressType, localAddress, remoteAddressType, remoteAddress, smpPassKey) {
  this._aclStream = aclStream;
  this.remoteAddress = remoteAddress;
  this.smpPassKey = smpPassKey;

  this._iat = new Buffer([(remoteAddressType === 'random') ? 0x01 : 0x00]);
  this._ia = new Buffer(remoteAddress.split(':').reverse().join(''), 'hex');
  this._rat = new Buffer([(localAddressType === 'random') ? 0x01 : 0x00]);
  this._ra = new Buffer(localAddress.split(':').reverse().join(''), 'hex');

  this._stk = null;
  this._random = null;
  this._diversifier = null;

  this.onAclStreamDataBinded = this.onAclStreamData.bind(this);
  this.onAclStreamEncryptChangeBinded = this.onAclStreamEncryptChange.bind(this);
  this.onAclStreamLtkNegReplyBinded = this.onAclStreamLtkNegReply.bind(this);
  this.onAclStreamEndBinded = this.onAclStreamEnd.bind(this);

  this._aclStream.on('data', this.onAclStreamDataBinded);
  this._aclStream.on('encryptChange', this.onAclStreamEncryptChangeBinded);
  this._aclStream.on('ltkNegReply', this.onAclStreamLtkNegReplyBinded);
  this._aclStream.on('end', this.onAclStreamEndBinded);
};

util.inherits(Smp, events.EventEmitter);

Smp.prototype.sendSecurityRequest = function () {
  this.write(Buffer.from([
    SMP_SECURE_REQ,
    0x05
  ]));
}

Smp.prototype.onAclStreamData = function (cid, data) {
  if (cid !== SMP_CID) {
    return;
  }

  var code = data.readUInt8(0);

  debug('onAclStreamData: ' + data.toString('hex'));
  debug('  code = 0x' + crypto.toHex(code));
  debug('  data = ' + data.slice(1).toString('hex'));

  if (SMP_PAIRING_REQUEST === code) {
    this.handlePairingRequest(data);
  } else if (SMP_PAIRING_CONFIRM === code) {
    this.handlePairingConfirm(data);
  } else if (SMP_PAIRING_RANDOM === code) {
    this.handlePairingRandom(data);
  } else if (SMP_PAIRING_FAILED === code) {
    this.handlePairingFailed(data);
  } else if (SMP_ENCRYPT_INFO === code) {
    this.handleEncryptInfo(data);
  } else if (SMP_MASTER_IDENT === code) {
    this.handleMasterIdent(data);
  }
};

Smp.prototype.onAclStreamEncryptChange = function (encrypted) {
  setTimeout(() => {
    if (encrypted) {
      if (this._stk && this._diversifier && this._random) {
        // Lets send the keys we have to send
        const responderKeyDistribution = this._pres.readUInt8(6);
        const linkKey = !!((responderKeyDistribution >> 3) & 1);
        const CSRK = !!((responderKeyDistribution >> 2) & 1);
        const IRK = !!((responderKeyDistribution >> 1) & 1);
        const LTK = !!(responderKeyDistribution & 1);
        debug('onAclStreamEncryptChange')
        debug('\tResponderKeyDistribution = 0x' + crypto.toHex(responderKeyDistribution));
        debug('\t\tLinkKey = ' + linkKey);
        debug('\t\tCSRK = ' + CSRK);
        debug('\t\tIRK = ' + IRK);
        debug('\t\tLTK = ' + LTK);

        if (CSRK) {
          this._csrk = crypto.r();
          this.write(Buffer.concat([
            new Buffer([SMP_SIGN_INFO]),
            this._csrk
          ]));
        }

        if (IRK) {
          this._irk = crypto.r();
          this.write(Buffer.concat([
            new Buffer([SMP_IDENT_INFO]),
            this._irk
          ]));
        }

        if (LTK) {
          this.write(Buffer.concat([
            new Buffer([SMP_ENCRYPT_INFO]),
            this._stk
          ]));
        }

        this.write(Buffer.concat([
          new Buffer([SMP_ADDR_INFO]),
          this._rat,
          this._ra
        ]));

        this.write(Buffer.concat([
          new Buffer([SMP_MASTER_IDENT]),
          this._diversifier,
          this._random
        ]));
      }
    }
  }, 400);
};

Smp.prototype.onAclStreamLtkNegReply = function () {
  this.write(new Buffer([
    SMP_PAIRING_FAILED,
    SMP_UNSPECIFIED
  ]));

  this.emit('fail');
};

Smp.prototype.onAclStreamEnd = function () {
  this._aclStream.removeListener('data', this.onAclStreamDataBinded);
  this._aclStream.removeListener('encryptChange', this.onAclStreamEncryptChangeBinded);
  this._aclStream.removeListener('ltkNegReply', this.onAclStreamLtkNegReplyBinded);
  this._aclStream.removeListener('end', this.onAclStreamEndBinded);
};

Smp.prototype.handlePairingRequest = function (data) {
  this._preq = data;

  debug('handlePairingRequest: ' + this._preq.toString('hex'));
  debug('\tcode = 0x' + crypto.toHex(this._preq.readUInt8(0)));
  debug('\tIO capability = 0x' + crypto.toHex(this._preq.readUInt8(1)));
  debug('\tOOB data = 0x' + crypto.toHex(this._preq.readUInt8(2)));
  debug('\tAuthentication = 0x' + crypto.toHex(this._preq.readUInt8(3)));
  debug('\t\t\tBonding Flags = ' + (this._preq.readUInt8(3) >> 6));
  debug('\t\t\tMITM = ' + ((this._preq.readUInt8(3) >> 5) & 1));
  debug('\t\t\tSC = ' + ((this._preq.readUInt8(3) >> 4) & 1));
  debug('\t\t\tKeypress = ' + ((this._preq.readUInt8(3) >> 3) & 1));
  debug('\t\t\tCT2 = ' + ((this._preq.readUInt8(3) >> 2) & 1));
  debug('\t\t\tRFU = ' + (this._preq.readUInt8(3) & 3));
  debug('\tMax encryption key size = 0x' + crypto.toHex(this._preq.readUInt8(4)));
  debug('\tInitiator key distribution = 0x' + crypto.toHex(this._preq.readUInt8(5)));
  debug('\tResponder key distribution = 0x' + crypto.toHex(this._preq.readUInt8(6)));

  // Fixed response
  this._pres = new Buffer([
    SMP_PAIRING_RESPONSE,
    0x02, // IO capability: NoInputNoOutput
    0x00, // OOB data: Authentication data not present
    0x05, // Authentication requirement: Bonding - No MITM
    0x10, // Max encryption key size
    0x00, // Initiator key distribution: <none>
    0x02  // Responder key distribution: EncKey, CSRK
  ]);

  debug('\tAnswering with: ' + this._pres.toString('hex'));
  debug('\t\tcode = 0x' + crypto.toHex(this._pres.readUInt8(0)));
  debug('\t\tIO capability = 0x' + crypto.toHex(this._pres.readUInt8(1)));
  debug('\t\tOOB data = 0x' + crypto.toHex(this._pres.readUInt8(2)));
  debug('\t\tAuthentication = 0x' + crypto.toHex(this._pres.readUInt8(3)));
  debug('\t\t\tBonding Flags = ' + (this._pres.readUInt8(3) >> 6));
  debug('\t\t\tMITM = ' + ((this._pres.readUInt8(3) >> 5) & 1));
  debug('\t\t\tSC = ' + ((this._pres.readUInt8(3) >> 4) & 1));
  debug('\t\t\tKeypress = ' + ((this._pres.readUInt8(3) >> 3) & 1));
  debug('\t\t\tCT2 = ' + ((this._pres.readUInt8(3) >> 2) & 1));
  debug('\t\t\tRFU = ' + (this._pres.readUInt8(3) & 3));
  debug('\t\tMax encryption key size = 0x' + crypto.toHex(this._pres.readUInt8(4)));
  debug('\t\tInitiator key distribution = 0x' + crypto.toHex(this._pres.readUInt8(5)));
  debug('\t\tResponder key distribution = 0x' + crypto.toHex(this._pres.readUInt8(6)));

  this.write(this._pres);
};

Smp.prototype.buildLegacyJustWorksPairingResponse = function () {
  debug('buildLegacyJustWorksPairingResponse')
  this._tk = Buffer.alloc(16, 0);
  this._r = crypto.r();

  return Buffer.concat([
    new Buffer([SMP_PAIRING_CONFIRM]),
    crypto.c1(this._tk, this._r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
  ]);
};

Smp.prototype.buildLegacyPasskeyPairingResponse = function () {
  debug('buildLegacyPasskeyPairingResponse')
  debug('\tPassKey = ' + this.smpPassKey)
  this._tk = Buffer.alloc(16, 0);
  this._tk.writeUInt32LE(Number(this.smpPassKey || 0), 0);
  this._r = crypto.r();

  return Buffer.concat([
    new Buffer([SMP_PAIRING_CONFIRM]),
    crypto.c1(this._tk, this._r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
  ]);
};

Smp.prototype.handlePairingConfirm = function (data) {
  this._pcnf = data;

  debug('handlePairingConfirm: ' + this._pcnf.toString('hex'));

  // Determine authentication type and assocation model.
  var authMethod = this.identifyAuthenticationMethod();
  this._authType = authMethod[0];
  this._assocModel = authMethod[1];
  var response = null;
  debug('\t\tauthType = ' + crypto.toHex(this.authType));
  debug('\t\tassocModel = ' + crypto.toHex(this._assocModel));


  if (this._authType === SMP_AUTH_LEGACY) {
    if (this._assocModel === SMP_MODEL_JUSTWORKS) {
      response = this.buildLegacyJustWorksPairingResponse();
    } else if (this._assocModel === SMP_MODEL_PASSKEY) {
      response = this.buildLegacyPasskeyPairingResponse();
    } else if (this._assocModel === SMP_MODEL_OOB) {
      debug('\t\tOOB pairing not currently supported.');
    } else {
      debug('\t\tUnexpected value for association model.');
    }
  } else if (this._authType === SMP_AUTH_LESC) {
    debug('\t\tSupport for LESC not available at present.');
  } else {
    debug('\t\tUnexpected value for authentication type (must be either LE Legacy or LESC)');
  }

  if (response) {
    debug('\tAnswering with: ' + response.toString('hex'));

    debug('\t\tTK = ' + this._tk.toString('hex'));
    debug('\t\tSrand = ' + this._r.toString('hex'));
    debug('\t\tPreq = ' + this._preq.toString('hex'));
    debug('\t\tPres = ' + this._pres.toString('hex'));
    debug('\t\tRat = ' + this._rat.toString('hex'));
    debug('\t\tRa = ' + this._ra.toString('hex'));
    debug('\t\tIat = ' + this._iat.toString('hex'));
    debug('\t\tIa = ' + this._ia.toString('hex'));

    this.write(response);
  } else {
    this.emit('fail', 'unsupported auth');
  }
};

/* BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part H, Section 2.3.5.1 */
Smp.prototype.identifyAuthenticationMethod = function () {
  // Get field values from Pairing Request.
  this._preqIo = this._preq.readUInt8(1);
  this._preqOob = this._preq.readUInt8(2);
  var preqAuthReqHex = this._preq.readUInt8(3);
  this._preqMitm = (preqAuthReqHex >> 2) & 1;
  this._preqLesc = (preqAuthReqHex >> 3) & 1;

  // Get field values from Pairing Response.
  this._presIo = this._pres.readUInt8(1);
  this._presOob = this._pres.readUInt8(2);
  var presAuthReq = this._pres.readUInt8(3);
  this._presMitm = (presAuthReq >> 2) & 1;
  this._presLesc = (presAuthReq >> 3) & 1;

  var authType = null;
  if ((this._preqLesc === 1) && (this._presLesc === 1)) {
    authType = SMP_AUTH_LESC;
  } else {
    authType = SMP_AUTH_LEGACY;
  }

  var assocModel = null;
  if (authType === SMP_AUTH_LEGACY) {
    if ((this._preqOob === SMP_OOB_YES) && (this._presOob === SMP_OOB_YES)) {
      // If both devices have OOB set, then use OOB.
      assocModel = SMP_MODEL_OOB;    
    } else if ((this._preqMitm === 0) && (this._presMitm === 0)) {
      // If neither device requires MITM protection, then use Just Works.
      assocModel = SMP_MODEL_JUSTWORKS;
    } else {
      // If either device requires MITM protection, then consider IO capabilities.
      assocModel = this.parseIoCapabilities(this._preqIo, this._presIo, authType);
    }
  } else {
    assocModel = null;
  }
  
  return [authType, assocModel];
};

Smp.prototype.parseIoCapabilities = function (reqIo, resIo, authType) {
  var ioAssocModel = null;
  if (authType === SMP_AUTH_LEGACY) {
    if ((reqIo === SMP_IO_NOINPUTNOOUTPUT) || (resIo === SMP_IO_NOINPUTNOOUTPUT)) {
      // Both devices are No Input No Output => Just Works.
      ioAssocModel = SMP_MODEL_JUSTWORKS;
    } else if ((reqIo === SMP_IO_DISPLAYONLY) && (resIO === SMP_IO_DISPLAYONLY)) {
      // Both devices are Display Only => Just Works.
      ioAssocModel = SMP_MODEL_JUSTWORKS;
    } else if ((reqIo === SMP_IO_DISPLAYYESNO) || (resIo === SMP_IO_DISPLAYYESNO)) {
      // At least one device is Display YesNo => Just Works.
      ioAssocModel = SMP_MODEL_JUSTWORKS;
    } else {
      // IO capabilities for LE Legacy result in Passkey Entry.
      ioAssocModel = SMP_MODEL_PASSKEY;
    }
  } else {
    // LESC not supported right now.
  }
  return ioAssocModel;
};


Smp.prototype.handlePairingRandom = function (data) {
  var r = data.slice(1);

  debug('handlePairingRandom: ' + data.toString('hex'));
  debug('\tMrand = ' + r.toString('hex'));

  var pcnf = Buffer.concat([
    new Buffer([SMP_PAIRING_CONFIRM]),
    crypto.c1(this._tk, r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
  ]);

  var response;
  if (this._pcnf.toString('hex') === pcnf.toString('hex')) {
    this._diversifier = new Buffer('0000', 'hex');
    this._random = new Buffer('0000000000000000', 'hex');
    this._stk = crypto.s1(this._tk, this._r, r);

    debug('\tPARING OK')
    debug('\tSTK = ' + this._stk.toString('hex'));
    this.emit('paired', {
      remoteAddress: this.remoteAddress,
      stk: this._stk,
      random: this._random,
      diversifier: this._diversifier
    });

    mgmt.addLongTermKey(this._ia, this._iat, 0, 0, this._diversifier, this._random, this._stk);

    response = Buffer.concat([
      new Buffer([SMP_PAIRING_RANDOM]),
      this._r
    ]);
  } else {
    response = new Buffer([
      SMP_PAIRING_FAILED,
      SMP_PAIRING_CONFIRM
    ]);

    debug('\tPARING FAIL')
    debug('\tMconfirm received = ' + this._pcnf.toString('hex'));
    debug('\tMconfirm expected = ' + pcnf.toString('hex'));
    this.emit('fail');
  }

  debug('\tAnswering with:  ' + response.toString('hex'));

  this.write(response);
};

Smp.prototype.handlePairingFailed = function (data) {
  debug('handlePairingFailed: ' + data.toString('hex'));
  debug('\tcode = 0x' + crypto.toHex(data.readUInt8(1)));

  this.emit('fail');
};

Smp.prototype.handleEncryptInfo = function (data) {
  var ltk = data.slice(1);
  debug('handleEncryptInfo');
  debug('\tLTK = ' + ltk.toString('hex'));

  this.emit('ltk', ltk);
};

Smp.prototype.handleMasterIdent = function (data) {
  var ediv = data.slice(1, 3);
  var rand = data.slice(3);
  debug('handleMasterIdent');
  debug('\tEDIV = ' + ediv.toString('hex'));
  debug('\tRAND = ' + rand.toString('hex'));

  this.emit('masterIdent', ediv, rand);
};

Smp.prototype.write = function (data) {
  this._aclStream.write(SMP_CID, data);
};

module.exports = Smp;
