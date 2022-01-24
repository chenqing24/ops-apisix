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
local core = require("apisix.core")
local jwt      = require("resty.jwt")
local ck       = require("resty.cookie")
local consumer = require("apisix.consumer")
local http     = require("resty.http")
local json     = require("apisix.core.json")
local sub_str  = string.sub

local schema = {
    type = "object",
    properties = {}
}

-- 常量 自身插件名
local plugin_name = "acl-plugin"
-- 常量 acl验证的服务地址，与ops-auth的ip端口绑定
local acl_server = "http://0.0.0.0:10010"


local _M = {
    version = 0.1,
    priority = 0,        -- TODO: add a type field, may be a good idea
    name = plugin_name,
    schema = schema,
}


local create_consume_cache
do
    local consumer_ids = {}

    function create_consume_cache(consumers)
        core.table.clear(consumer_ids)

        for _, consumer in ipairs(consumers.nodes) do
            core.log.info("consumer node: ", core.json.delay_encode(consumer))
            consumer_ids[consumer.auth_conf.appid] = consumer
        end

        return consumer_ids
    end

end -- do


local function fetch_jwt_token(ctx)
    -- 从请求中获得token
    local token = core.request.header(ctx, "authorization")
    if token then
        local prefix = sub_str(token, 1, 7)
        if prefix == 'Bearer ' or prefix == 'bearer ' then
            return sub_str(token, 8)
        end
        return token
    end

    token = ctx.var.arg_jwt
    if token then
        return token
    end

    local cookie, err = ck:new()
    if not cookie then
        return nil, err
    end

    local val, err = cookie:get("jwt")
    return val, err
end


local function new_headers()
    -- 子请求的头
    local t = {}
    local lt = {}
    local _mt = {
        __index = function(t, k)
            return rawget(lt, string.lower(k))
        end,
        __newindex = function(t, k, v)
            rawset(t, k, v)
            rawset(lt, string.lower(k), v)
        end,
     }
    return setmetatable(t, _mt)
end


local function http_req(method, uri, body, myheaders, timeout)
    -- 子请求构造，timeout单位ms 
    if myheaders == nil then myheaders = new_headers() end

    local httpc = http.new()
    if timeout then
        httpc:set_timeouts(timeout, timeout, timeout)
    end

    local params = {method = method, headers = myheaders, body = body, keepalive = false, ssl_verify = false}
    
    -- TODO 验证access_check_url 域名变ip:port
    core.log.error("http_req.uri: ", uri, ", timeout: ", timeout)
    local res, err = httpc:request_uri(uri, params)

    if err then
        core.log.error("FAIL REQUEST [ ",core.json.delay_encode(
            {method = method, uri = uri, body = body, headers = myheaders}),
            " ] failed! res is nil, err:", err)
        return nil, err
    end

    return res
end


local function http_post(uri, body, myheaders, timeout)
    -- post请求方法 
    return http_req("POST", uri, body, myheaders, timeout)
end


function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)

    if not ok then
        return false, err
    end

    return true
end


local function check_url_acl(server, user_name, action, res_name)
    -- 验证acl
    -- 入参: acl服务接口地址，用户名，req的method，uri
    local retry_max = 3
    local errmsg
    
    local res
    local err
    local access_check_url = server .. "/account/acl_check"
    -- TODO 验证access_check_url 域名变ip:port
    core.log.error("access_check_url:", access_check_url)

    local headers = new_headers()
    headers["Content-Type"] = "application/json; charset=utf-8"

    local args = { res_name = res_name, method = action, user_name = user_name}
    local timeout = 1000 * 10

    for i = 1, retry_max do
        -- TODO: read apisix info.
        res, err = http_post(access_check_url, core.json.encode(args), headers, timeout)
        if err then
            break
        else
            core.log.info("check permission request:", url, ", status:", res.status,
                            ",body:", core.json.delay_encode(res.body))
            if res.status < 500 then
                break
            else
                core.log.info("request [curl -v ", url, "] failed! status:", res.status)
                if i < retry_max then
                    ngx.sleep(0.1)
                end
            end
        end
    end

    if err then
        -- 访问acl-server异常 
        return {status = 500, err = "request to acl-server failed, err:" .. tostring(err)}
    end

    if res.status ~= 200 and res.status ~= 403 then
        -- 非200和403的未知http码
        return {status = 500, err = 'request to acl-server failed, status:' .. tostring(res.status)}
    end

    local body, err = json.decode(res.body)
    if err then
        errmsg = 'check permission failed! parse response json failed!'
        return {status = res.status, err = errmsg}
    else
        return {status = res.status}
    end
end


function _M.rewrite(conf, ctx)
    -- 在access之前验证
    -- fix 生产上直接用域名
    -- local url = ctx.var.scheme .. "://" .. ctx.var.server_addr .. ":" .. ctx.var.server_port .. ctx.var.uri
    local url = ctx.var.scheme .. "://" .. ctx.var.host .. ctx.var.uri
    core.log.error("url: ", url)

    local action = ctx.var.request_method

    -- 如果是游览器为了跨域而发的OPTIONS，直接返回OK
    if 'OPTIONS' == action then
        return 200
    end
    core.log.error("action: ", action)
    
    local jwt_token, err = fetch_jwt_token(ctx)
    if not jwt_token then
        if err and err:sub(1, #"no cookie") ~= "no cookie" then
            core.log.error("failed to fetch JWT token: ", err)
        end

        return 401, {message = "Missing JWT token in request"}
    end
    core.log.error("jwt_token: ", jwt_token)

    local jwt_obj = jwt:load_jwt(jwt_token)
    if not jwt_obj.valid then
        return 401, {message = jwt_obj.reason}
    end

    -- 从token中提取用户信息
    local user_key = jwt_obj.payload and jwt_obj.payload.key
    if not user_key then
        return 401, {message = "missing user key in JWT token"}
    end
    core.log.error("user_key: ", user_key)

    local res = check_url_acl(acl_server, user_key, action, url)

    if res.status ~= 200 then
        -- no permission.
        core.log.error(" check_url_acl(", core.json.delay_encode(permItem),
            ") failed, res: ",core.json.delay_encode(res))
            return 401, {message = "no permission."}
    end
    
    core.log.info("acl check permission passed")
end


return _M
