'use strict'

const figgyPudding = require('figgy-pudding')
const npa = require('npm-package-arg')
const npmFetch = require('npm-registry-fetch')
const validate = require('aproba')

const AccessConfig = figgyPudding({
  Promise: {default: () => Promise}
})

const eu = encodeURIComponent
const cmd = module.exports = {}

cmd.public = (spec, opts) => setAccess(spec, 'public', opts)
cmd.restricted = (spec, opts) => setAccess(spec, 'restricted', opts)
function setAccess (spec, access, opts) {
  opts = AccessConfig(opts)
  return new opts.Promise((resolve, reject) => {
    spec = npa(spec)
    validate('OSO', [spec, access, opts])
    const uri = `/-/package/${eu(spec.name)}/access`
    return npmFetch.json(uri, opts.concat({
      method: 'POST',
      body: {access},
      spec
    })).then(resolve, reject)
  })
}

cmd.grant = (spec, scope, team, permissions, opts) => {
  opts = AccessConfig(opts)
  return new opts.Promise((resolve, reject) => {
    spec = npa(spec)
    validate('OSSSO', [spec, scope, team, permissions, opts])
    scope = scope.replace(/^@/, '')
    if (permissions !== 'read-write' && permissions !== 'read-only') {
      throw new Error('`permissions` must be `read-write` or `read-only`. Got `' + permissions + '` instead')
    }
    const uri = `/-/team/${eu(scope)}/${eu(team)}/package`
    return npmFetch.json(uri, opts.concat({
      method: 'PUT',
      body: {package: spec.name, permissions},
      scope,
      spec
    })).then(resolve, reject)
  })
}

cmd.revoke = (spec, scope, team, opts) => {
  opts = AccessConfig(opts)
  return new opts.Promise((resolve, reject) => {
    spec = npa(spec)
    validate('OSSO', [spec, scope, team, opts])
    scope = scope.replace(/^@/, '')
    const uri = `/-/team/${eu(scope)}/${eu(team)}/package`
    return npmFetch.json(uri, opts.concat({
      method: 'DELETE',
      body: {package: spec.name},
      scope,
      spec
    })).then(resolve, reject)
  })
}

cmd.lsPackages = (scope, team, opts) => {
  opts = AccessConfig(opts)
  return new opts.Promise((resolve, reject) => {
    validate('SSO|SZO', [scope, team, opts])
    scope = scope.replace(/^@/, '')
    let uri
    if (team) {
      uri = `/-/org/${eu(scope)}/${eu(team)}/package`
    } else {
      uri = `/-/org/${eu(scope)}/package`
    }
    opts = opts.concat({query: {format: 'cli'}})
    return npmFetch.json(uri, opts).catch(err => {
      if (err.code === 'E404' && !team) {
        uri = `/-/user/${eu(scope)}/package`
        return npmFetch.json(uri, opts)
      } else {
        throw err
      }
    }).then(translatePermissions).then(resolve, reject)
  })
}

cmd.lsCollaborators = (spec, user, opts) => {
  opts = AccessConfig(opts)
  return new opts.Promise((resolve, reject) => {
    spec = npa(spec)
    validate('OSO|OZO', [spec, user, opts])
    const uri = `/-/package/${spec.escapedName}/collaborators`
    return npmFetch.json(uri, opts.concat({
      query: {user, format: 'cli'}
    })).then(translatePermissions).then(resolve, reject)
  })
}

function translatePermissions (perms) {
  if (!perms) { return null }
  const newPerms = {}
  for (let [key, val] of Object.entries(perms)) {
    if (val === 'read') {
      newPerms[key] = 'read-only'
    } else if (val === 'write') {
      newPerms[key] = 'read-write'
    } else {
      newPerms[key] = val
    }
  }
  return newPerms
}

cmd.tfaRequired = (spec, opts) => setRequires2fa(spec, true, opts)
cmd.tfaNotRequired = (spec, opts) => setRequires2fa(spec, false, opts)
function setRequires2fa (spec, required, opts) {
  opts = AccessConfig(opts)
  return new opts.Promise((resolve, reject) => {
    spec = npa(spec)
    validate('OBO', [spec, required, opts])
    const uri = `/-/package/${eu(spec.name)}/access`
    return npmFetch.json(uri, opts.concat({
      method: 'POST',
      body: {publish_requires_tfa: required},
      spec
    })).then(resolve, reject)
  })
}

cmd.edit = () => {
  throw new Error('Not implemented yet')
}
