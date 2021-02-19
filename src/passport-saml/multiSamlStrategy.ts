import * as util from "util";
import * as saml from "./saml";
import { CacheProvider as InMemoryCacheProvider } from "./inmemory-cache-provider";
import SamlStrategy = require("./strategy");
import type { Request } from "express";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  MultiSamlConfig,
  RequestWithUser,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "./types";

class MultiSamlStrategy extends SamlStrategy {
  _options: MultiSamlConfig;
  constructor(options: MultiSamlConfig, verify: VerifyWithRequest | VerifyWithoutRequest) {
    if (!options || typeof options.getSamlOptionsAsync != "function") {
      throw new Error(
        "Please provide a getSamlOptionsAsync function. getSamlOptions function is deprecated"
      );
    }

    if (!options.requestIdExpirationPeriodMs) {
      options.requestIdExpirationPeriodMs = 28800000; // 8 hours
    }

    if (!options.cacheProvider) {
      options.cacheProvider = new InMemoryCacheProvider({
        keyExpirationPeriodMs: options.requestIdExpirationPeriodMs,
      });
    }

    super(options, verify);
    this._options = options;
  }

  async authenticate(req: RequestWithUser, options: AuthenticateOptions & AuthorizeOptions) {
    let samlOptions;
    try {
      samlOptions = await this._options.getSamlOptionsAsync(req);
    } catch (err) {
      return this.error(err);
    }
    const samlService = new saml.SAML({ ...this._options, ...samlOptions });
    const strategy = Object.assign({}, this, { _saml: samlService });
    Object.setPrototypeOf(strategy, this);
    super.authenticate.call(strategy, req, options);
  }

  async logout(
    req: RequestWithUser,
    callback: (err: Error | null, url?: string | null | undefined) => void
  ) {
    let samlOptions;
    try {
      samlOptions = await this._options.getSamlOptionsAsync(req);
    } catch (err) {
      return callback(err);
    }
    const samlService = new saml.SAML(Object.assign({}, this._options, samlOptions));
    const strategy = Object.assign({}, this, { _saml: samlService });
    Object.setPrototypeOf(strategy, this);
    super.logout.call(strategy, req, callback);
  }

  generateServiceProviderMetadata(): string {
    throw new Error("Use generateServiceMetadataAsync method instead");
  }

  async generateServiceProviderMetadataAsync(
    req: Request,
    decryptionCert: string | null,
    signingCert: string | null
  ) {
    const samlOptions = await this._options.getSamlOptionsAsync(req);

    const samlService = new saml.SAML(Object.assign({}, this._options, samlOptions));
    const strategy = Object.assign({}, this, { _saml: samlService });
    Object.setPrototypeOf(strategy, this);
    return super.generateServiceProviderMetadata.call(strategy, decryptionCert, signingCert);
  }
}

export = MultiSamlStrategy;
