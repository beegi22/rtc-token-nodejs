const {RtcTokenBuilder, RtcRole} = require('./index')
let token = ""

const generateRtcToken = () => {
  // Rtc Examples
  const appID = '1f042c0c9f264ac0a9905aa65109007e';
  const appCertificate = '3df2ce4ca0e74aa7acbcd803b02fb17c';
  const channelName = '7d72365eb983485397e3e3f9d460bdda';

  const uid = 2882341273;
  const role = RtcRole.PUBLISHER;

  const expirationTimeInSeconds = 3600
  const privilegeExpire = 3600

  // IMPORTANT! Build token with either the uid or with the user account. Comment out the option you do not want to use below.

  // Build token with uid
  const tokenA = RtcTokenBuilder.buildTokenWithUid(appID, appCertificate, channelName, uid, role, expirationTimeInSeconds, privilegeExpire);
  console.log("Token With Integer Number Uid: " + tokenA);
}

generateRtcToken()


