var debug = require('debug')('acl-att-stream');

var events = require('events');
var util = require('util');

var crypto = require('./crypto');
var Smp = require('./smp');

var AclStream = function(hci, handle, localAddressType, localAddress, remoteAddressType, remoteAddress, smpPassKey) {
  this._hci = hci;
  this._handle = handle;
  this.encypted = false;

  this._smp = new Smp(this, localAddressType, localAddress, remoteAddressType, remoteAddress, smpPassKey);
};

util.inherits(AclStream, events.EventEmitter);


AclStream.prototype.write = function(cid, data) {
  this._hci.queueAclDataPkt(this._handle, cid, data);
};

AclStream.prototype.push = function(cid, data) {
  if (data) {
    debug('AclStreamData');
    debug('\tcid = 0x' + crypto.toHex(cid));
    debug('\tdata = ' + data.toString('hex'));
    this.emit('data', cid, data);
  } else {
    this.emit('end');
  }
};

AclStream.prototype.pushEncrypt = function(encrypt) {
  this.encrypted = encrypt ? true : false;

  this.emit('encryptChange', this.encrypted);
};

AclStream.prototype.pushLtkNegReply = function() {
  this.emit('ltkNegReply');
};

module.exports = AclStream;
