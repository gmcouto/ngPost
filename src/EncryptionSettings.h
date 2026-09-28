#ifndef ENCRYPTIONSETTINGS_H
#define ENCRYPTIONSETTINGS_H

#include <QString>

struct EncryptionSettings
{
    bool enabled = false;
    bool controlLines = true;
    QString password;

    bool validate(QString *error = nullptr) const
    {
        if(enabled && password.isEmpty())
        {
            if(error)
                *error = QStringLiteral("Encryption requires a non-empty password");
            return false;
        }
        if(enabled && !controlLines)
        {
            if(error)
                *error = QStringLiteral("Encryption requires control-line encryption");
            return false;
        }
        return true;
    }

    void clearPassword()
    {
        password.detach();
        password.fill(QChar(0));
        password.clear();
    }
};

#endif
