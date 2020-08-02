// Copyright (c) 2020-present Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>

namespace libtorrent {
    class entry;
}
class CKeyID;

class CBdapTorrent
{
public:
    std::string strErrorMessage;
    int k;

    CBdapTorrent(): strErrorMessage(""), k(0) {}

    bool CreateDirectMessage(libtorrent::entry& dm, const std::vector<unsigned char>& vchSharedPubKey, const std::vector<unsigned char>& vchMessage);
    bool NewDirectMessage(const std::vector<unsigned char>& vchFrom, const std::vector<unsigned char>& vchTo, const std::vector<unsigned char>& vchMessage);
    bool CreateSignedMessage(libtorrent::entry& v, const std::vector<unsigned char>& vchUserFQDN,
                        const std::vector<unsigned char>& vchPubKey,
                        const std::string& msg, const libtorrent::entry* ent);
    bool CheckSignature(const std::vector<unsigned char>& vchPubKey) const;
    std::string CreateTorrentSignature(const std::string& strMessage, const std::vector<unsigned char>& vchPubKey, const std::vector<unsigned char>& vchPrivKey) const;
    bool VerifyTorrentSignature(const std::string& strMessage, const std::string& strPubKey, const std::string& strSign) const;
};
