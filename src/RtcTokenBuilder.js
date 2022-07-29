const AccessToken = require('../src/AccessToken').AccessToken
const ServiceRtc = require('../src/AccessToken').ServiceRtc

const Role = {
    // for live broadcaster
    PUBLISHER: 1,

    // default, for live audience
    SUBSCRIBER: 2,
}

class RtcTokenBuilder {
    /**
     * Builds an RTC token using an Integer uid.
     * @param {*} appId  The App ID issued to you by Agora.
     * @param {*} appCertificate Certificate of the application that you registered in the Agora Dashboard.
     * @param {*} channelName The unique channel name for the AgoraRTC session in the string format. The string length must be less than 64 bytes. Supported character scopes are:
     * - The 26 lowercase English letters: a to z.
     * - The 26 uppercase English letters: A to Z.
     * - The 10 digits: 0 to 9.
     * - The space.
     * - "!", "#", "$", "%", "&", "(", ")", "+", "-", ":", ";", "<", "=", ".", ">", "?", "@", "[", "]", "^", "_", " {", "}", "|", "~", ",".
     * @param {*} uid User ID. A 32-bit unsigned integer with a value ranging from 1 to (2^32-1).
     * @param {*} role See #userRole.
     * - Role.PUBLISHER; RECOMMENDED. Use this role for a voice/video call or a live broadcast.
     * - Role.SUBSCRIBER: ONLY use this role if your live-broadcast scenario requires authentication for [Hosting-in](https://docs.agora.io/en/Agora%20Platform/terms?platform=All%20Platforms#hosting-in). In order for this role to take effect, please contact our support team to enable authentication for Hosting-in for you. Otherwise, Role_Subscriber still has the same privileges as Role_Publisher.
     * @param {*} token_expire epresented by the number of seconds elapsed since now. If, for example, you want to access the Agora Service within 10 minutes after the token is generated, set token_expire as 600(seconds)
     * @param {*} privilege_expire represented by the number of seconds elapsed since now. If, for example, you want to enable your privilege for 10 minutes, set privilege_expire as 600(seconds).     * @return The new Token.
     */
    static buildTokenWithUid(appId, appCertificate, channelName, uid, role,  token_expire, privilege_expire = 0) {
        let token = new AccessToken(appId, appCertificate, 0, token_expire)

        let serviceRtc = new ServiceRtc(channelName, uid)
        serviceRtc.add_privilege(ServiceRtc.kPrivilegeJoinChannel, privilege_expire)
        if (role == Role.PUBLISHER) {
            serviceRtc.add_privilege(ServiceRtc.kPrivilegePublishAudioStream, privilege_expire)
            serviceRtc.add_privilege(ServiceRtc.kPrivilegePublishVideoStream, privilege_expire)
            serviceRtc.add_privilege(ServiceRtc.kPrivilegePublishDataStream, privilege_expire)
        }
        token.add_service(serviceRtc)

        return token.build()
    }
}

module.exports.RtcTokenBuilder = RtcTokenBuilder
module.exports.Role = Role
