--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core      = require("apisix.core")
local http      = require "resty.http"
local sub_str   = string.sub
local url       = require "net.url"
local tostring  = tostring
local ngx       = ngx
local plugin_name = "third-auth"



local schema = {
    type = "object",
    properties = {
        third_url = {type = "string", minLength = 1, maxLength = 4096},
        timeout = {type = "integer", minimum = 1000, default = 3000},
        keepalive = {type = "boolean", default = true},
        keepalive_timeout = {type = "integer", minimum = 1000, default = 60000},
        keepalive_pool = {type = "integer", minimum = 1, default = 5},
        ssl_verify = {type = "boolean", default = true},
    },
    required = {"third_url"}
}


local _M = {
    version = 0.1,
    priority = 3000,
    type = 'auth',
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function fetch_req_data(ctx)
    local uri_args = ngx.req.get_uri_args() or {}
    local headers = ngx.req.get_headers() or {}
    local body = ngx.req.read_body() or {}
    local post_args = ngx.req.get_post_args() or {}
    return {
        ip = core.request.get_ip(ctx),
        remote_client_ip = core.request.get_remote_client_ip(ctx),
        host = core.request.get_host(ctx),
        port = core.request.get_port(ctx),
        http_version = core.request.get_http_version(ctx),
        uri_args = core.json.encode(uri_args),
        post_args = core.json.encode(post_args),
        headers = core.json.encode(headers),
    }
end

local function fetch_token(ctx)
    local token = core.request.header(ctx, "authorization")
    if not token then
        return nil
    end

    return token
end

local function evaluate_permissions(conf, req_data, token)
    local url_decoded = url.parse(conf.third_url)
    local host = url_decoded.host
    local port = url_decoded.port

    if not port then
        if url_decoded.scheme == "https" then
            port = 443
        else
            port = 80
        end
    end

    local httpc = http.new()
    httpc:set_timeout(conf.timeout)

    local params = {
        method = "POST",
        body =  ngx.encode_args({
            ip=req_data.ip,
            remote_client_ip=req_data.remote_client_ip,
            host=req_data.host,
            port=req_data.port,
            http_version=req_data.http_version,
            headers=req_data.headers,
            uri_args=req_data.uri_args,
            post_args=req_data.post_args,
        }),
        ssl_verify = conf.ssl_verify,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
            ["Authorization"] = token,
        }
    }

    if conf.keepalive then
        params.keepalive_timeout = conf.keepalive_timeout
        params.keepalive_pool = conf.keepalive_pool
    else
        params.keepalive = conf.keepalive
    end

    local httpc_res, httpc_err = httpc:request_uri(conf.third_url, params)

    if not httpc_res then
        core.log.error("error while sending authz request to [", host ,"] port[",tostring(port), "] ", httpc_err)
        return 500, httpc_err
    end

    if httpc_res.status >= 400 then
        core.log.error("status code: ", httpc_res.status, " msg: ", httpc_res.body)
        return httpc_res.status, httpc_res.body
    end
end



function _M.rewrite(conf, ctx)
    core.log.debug("hit third-auth rewrite")

    local req_data = fetch_req_data(ctx)
    local token = fetch_token(ctx)

    local status, body = evaluate_permissions(conf, req_data, token)
    if status then
        return status, body
    end
end


return _M
