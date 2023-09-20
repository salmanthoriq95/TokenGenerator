import CryptoJS from 'crypto-js';

interface IToken {
  token: string;
  key: string;
}

interface IDecodedToken {
  status: string;
  payload?: object;
  newToken?: string;
  key?: string;
  createdAt?: number;
}

interface ITokenPayload {
  payload: object | string;
  secretKey?: string;
  secretKeyLength?: number;
  withRefresher?: boolean;
  accessTokenExpiredIn?: number;
  refresherExpiredIn?: number;
}

interface ITokenVerifiedPayload {
  token: string;
  secretKey: string;
  isKeyRandom?: boolean;
  randomKeyLength?: number;
}

class TokenGenerator {
  /**
   *
   * @param keyLength Length of random secret key; default is 6 random chars
   * @returns returning the random chars
   */
  private generateSecretKey(keyLength: number = 6): string {
    const characters =
      '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let result = '';
    for (let i = 0; i < keyLength; i++) {
      result += characters.charAt(
        Math.floor(Math.random() * characters.length)
      );
    }
    return result;
  }

  /**
   *
   * @param tokenParams.payload Object, Mandatory. It is the body you want to pass into the token
   * @param tokenParams.[secretKey] String, Optional. The default is random char depend on secretKeyLength key object
   * @param tokenParams.[secretKeyLength] Number, Optional. The default is 6 random char, it will use when the secretKey is not passed
   * @param tokenParams.[withRefresher] Boolean, Optional. The dafault is false
   * @param tokenParams.[accessTokenExpiredIn] Number, Optional. The default is no expired
   * @param tokenParams.[refresherExpiredIn] Number, Optional. The default is no expired
   * @returns An object contain new token and it secret key
   */
  generateToken(tokenParams: ITokenPayload): IToken {
    const currentDate = new Date().getTime();
    const secretKey =
      tokenParams.secretKey ??
      this.generateSecretKey(tokenParams.secretKeyLength);

    const payloadBody = {
      payload: tokenParams.payload,
      createdAt: currentDate,
      accessExpiredAt: tokenParams.accessTokenExpiredIn
        ? currentDate + tokenParams.accessTokenExpiredIn
        : undefined,
      refresherExpiredAt: tokenParams.refresherExpiredIn
        ? currentDate + tokenParams.refresherExpiredIn
        : undefined,
    };

    return {
      token: CryptoJS.AES.encrypt(
        JSON.stringify(payloadBody),
        secretKey
      ).toString(),
      key: secretKey,
    };
  }

  /**
   *
   * @param tokenVerifierParams.token string, token that want to verifiy and decoded
   * @param tokenVerifierParams.secretKey string, secret key for decode the token
   * @param tokenVerifierParams.[isKeyRandom] boolean, is secret key is a random chars. default is false
   * @param tokenVerifierParams.[randomKeyLength] number, the length of random key. default is null
   * @returns An object contain status and payload
   */
  verifyToken(tokenVerifierParams: ITokenVerifiedPayload): IDecodedToken {
    let status = 'Token Verified';
    try {
      const rawDecyptedStr = CryptoJS.AES.decrypt(
        tokenVerifierParams.token,
        tokenVerifierParams.secretKey
      );
      const decyptedStr = rawDecyptedStr.toString(CryptoJS.enc.Utf8);
      const decryptToken = JSON.parse(decyptedStr);
      const currentDate = new Date().getTime();

      let token = tokenVerifierParams.token;
      let key = tokenVerifierParams.secretKey;

      if (decryptToken.refresherExpiredIn) {
        if (
          decryptToken.refresherExpiredIn < currentDate &&
          decryptToken.accessTokenExpiredIn &&
          decryptToken.accessTokenExpiredIn < currentDate
        )
          status =
            'Token verified but access token and refresher token expired!';
        if (
          decryptToken.refresherExpiredIn > currentDate &&
          decryptToken.accessTokenExpiredIn &&
          decryptToken.accessTokenExpiredIn < currentDate
        ) {
          status = 'Token verified but access token expired!';
          const accessExpRange =
            decryptToken.accessTokenExpiredIn - decryptToken.createdAt;
          const refresherExpRange =
            decryptToken.refresherExpiredIn - decryptToken.createdAt;

          key = !tokenVerifierParams.isKeyRandom
            ? tokenVerifierParams.secretKey
            : this.generateSecretKey(tokenVerifierParams.randomKeyLength);

          const newToken = this.generateToken({
            payload: decryptToken.payload,
            refresherExpiredIn: refresherExpRange,
            accessTokenExpiredIn: accessExpRange,
            secretKey: key,
            withRefresher: true,
          });

          token = newToken.token;
        }
      }

      if (!decryptToken.refresherExpiredIn) {
        if (
          decryptToken.accessTokenExpiredIn &&
          decryptToken.accessTokenExpiredIn < currentDate
        )
          status = 'Token verified but access token expired!';
      }

      return {
        status,
        payload: decryptToken.payload,
        createdAt: decryptToken.createdAt,
        key,
        newToken: token,
      };
    } catch (error) {
      return {
        status: 'Token not verifed!',
      };
    }
  }
}

export default new TokenGenerator();
