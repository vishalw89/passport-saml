"use strict";
import * as express from "express";
import * as sinon from "sinon";
import * as should from "should";
import { Strategy as SamlStrategy, MultiSamlStrategy } from "../src/passport-saml";
import { SamlConfig, SamlOptionsCallback } from "../src/passport-saml/types";

function verify() {}

describe("Strategy()", function () {
  it("extends passport Strategy", function () {
    async function getSamlOptionsAsync() {
      return {};
    }
    const strategy = new MultiSamlStrategy({ getSamlOptionsAsync: getSamlOptionsAsync }, verify);
    strategy.should.be.an.instanceOf(SamlStrategy);
  });

  it("throws if wrong finder is provided", function () {
    function createStrategy() {
      return new MultiSamlStrategy({} as any, verify);
    }
    should.throws(createStrategy);
  });
});

describe("strategy#authenticate", function () {
  beforeEach(function () {
    this.superAuthenticateStub = sinon.stub(SamlStrategy.prototype, "authenticate");
  });

  afterEach(function () {
    this.superAuthenticateStub.restore();
  });

  it("calls super with request and auth options", async function (done) {
    const superAuthenticateStub = this.superAuthenticateStub;

    const strategy = new MultiSamlStrategy(
      {
        getSamlOptionsAsync: async (req: express.Request) => {
          sinon.assert.calledOnce(superAuthenticateStub);
          done();
          return {};
        },
      },
      verify
    );
    strategy.authenticate("random" as any, "random" as any);
  });

  it("passes options on to saml strategy", function (done) {
    const passportOptions = {
      passReqToCallback: true,
      authnRequestBinding: "HTTP-POST",
      getSamlOptionsAsync: async function (req: express.Request) {
        strategy._passReqToCallback!.should.eql(true);
        strategy._authnRequestBinding!.should.eql("HTTP-POST");
        done();
        return {};
      },
    };

    var strategy = new MultiSamlStrategy(passportOptions, verify);
    strategy.authenticate("random" as any, "random" as any);
  });

  it("uses given options to setup internal saml provider", function (done) {
    const superAuthenticateStub = this.superAuthenticateStub;
    const samlOptions = {
      issuer: "http://foo.issuer",
      callbackUrl: "http://foo.callback",
      cert: "deadbeef",
      host: "lvh",
      acceptedClockSkewMs: -1,
      identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      path: "/saml/callback",
      logoutUrl: "http://foo.slo",
      signatureAlgorithm: "sha256" as const,
    } as SamlConfig;

    async function getSamlOptionsAsync(req: express.Request) {
      try {
        sinon.assert.calledOnce(superAuthenticateStub);
        superAuthenticateStub.calledWith(
          Object.assign({}, { cacheProvider: "mock cache provider" }, samlOptions)
        );
        done();
        return samlOptions;
      } catch (err2) {
        done(err2);
        throw err2;
      }
    }

    const strategy = new MultiSamlStrategy(
      { getSamlOptionsAsync: getSamlOptionsAsync, cacheProvider: "mock cache provider" as any },
      verify
    );
    strategy.authenticate("random" as any, "random" as any);
  });
});

describe("strategy#logout", function () {
  beforeEach(function () {
    this.superLogoutMock = sinon.stub(SamlStrategy.prototype, "logout");
  });

  afterEach(function () {
    this.superLogoutMock.restore();
  });

  it("calls super with request and auth options", async function () {
    const superLogoutMock = this.superLogoutMock;
    async function getSamlOptionsAsync(req: express.Request) {
      return {} as SamlConfig;
    }

    const strategy = new MultiSamlStrategy({ getSamlOptionsAsync: getSamlOptionsAsync }, verify);
    await strategy.logout("random" as any, "random" as any);
    sinon.assert.calledOnce(superLogoutMock);
  });

  it("passes options on to saml strategy", function (done) {
    const passportOptions = {
      passReqToCallback: true,
      authnRequestBinding: "HTTP-POST",
      getSamlOptionsAsync: async (req: express.Request) => {
        try {
          strategy._passReqToCallback!.should.eql(true);
          strategy._authnRequestBinding!.should.eql("HTTP-POST");
          done();
        } catch (err2) {
          done(err2);
        }
        return {};
      },
    };

    var strategy = new MultiSamlStrategy(passportOptions, verify);
    strategy.logout("random" as any, "random" as any);
  });

  it("uses given options to setup internal saml provider", async function () {
    const superLogoutMock = this.superLogoutMock;
    const samlOptions = {
      issuer: "http://foo.issuer",
      callbackUrl: "http://foo.callback",
      cert: "deadbeef",
      host: "lvh",
      acceptedClockSkewMs: -1,
      identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      path: "/saml/callback",
      logoutUrl: "http://foo.slo",
      signatureAlgorithm: "sha256" as const,
    } as SamlConfig;

    async function getSamlOptionsAsync(req: express.Request) {
      return samlOptions;
    }

    const strategy = new MultiSamlStrategy({ getSamlOptionsAsync: getSamlOptionsAsync }, verify);
    await strategy.logout("random" as any, sinon.spy());
    sinon.assert.calledOnce(superLogoutMock);
    superLogoutMock.calledWith(Object.assign({}, samlOptions));
  });
});

describe("strategy#generateServiceProviderMetadata", function () {
  beforeEach(function () {
    this.superGenerateServiceProviderMetadata = sinon
      .stub(SamlStrategy.prototype, "generateServiceProviderMetadata")
      .returns("My Metadata Result");
  });

  afterEach(function () {
    this.superGenerateServiceProviderMetadata.restore();
  });

  it("calls super with request and generateServiceProviderMetadata options", async function (done) {
    const superGenerateServiceProviderMetadata = this.superGenerateServiceProviderMetadata;
    async function getSamlOptionsAsync(req: express.Request) {
      try {
        sinon.assert.calledOnce(superGenerateServiceProviderMetadata);
        superGenerateServiceProviderMetadata.calledWith("bar", "baz");
        req.should.eql("foo");
        done();
        return {} as SamlConfig;
      } catch (err2) {
        done(err2);
        throw err2;
      }
    }

    const strategy = new MultiSamlStrategy({ getSamlOptionsAsync: getSamlOptionsAsync }, verify);
    await strategy.generateServiceProviderMetadataAsync("foo" as any, "bar", "baz");
  });

  it("passes options on to saml strategy", async function (done) {
    const passportOptions = {
      passReqToCallback: true,
      authnRequestBinding: "HTTP-POST",

      getSamlOptionsAsync: async function (req: express.Request) {
        try {
          strategy._passReqToCallback!.should.eql(true);
          strategy._authnRequestBinding!.should.eql("HTTP-POST");
          done();
          return {} as SamlConfig;
        } catch (err2) {
          done(err2);
          throw err2;
        }
      },
    };

    var strategy = new MultiSamlStrategy(passportOptions, verify);
    await strategy.generateServiceProviderMetadataAsync("foo" as any, "bar", "baz");
  });

  it("should pass error to callback function", async () => {
    const passportOptions = {
      getSamlOptionsAsync: function (req: express.Request) {
        throw new Error("My error");
      },
    };

    const strategy = new MultiSamlStrategy(passportOptions, verify);
    try {
      await strategy.generateServiceProviderMetadataAsync("foo" as any, "bar", "baz");
      should.ok(false, "Did not throw the error");
    } catch (error) {
      should(error?.message).equal("My error");
    }
  });

  it("should pass result to callback function", async () => {
    const passportOptions = {
      getSamlOptionsAsync: async function (req: express.Request) {
        return {};
      },
    };

    const strategy = new MultiSamlStrategy(passportOptions, verify);
    const result = await strategy.generateServiceProviderMetadataAsync("foo" as any, "bar", "baz");
    should(result).equal("My Metadata Result");
  });
});
