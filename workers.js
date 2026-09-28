					if (访问路径 === 'admin/cfaccountconfig') {// 六账户 Account ID / Token 配置页面
						if (request.method === 'GET') return new Response(await html六账户配置(env), { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' } });
						if (request.method === 'POST') {
							try {
								const body = await request.json();
								if (!Array.isArray(body?.accounts) || body.accounts.length !== 6) throw new Error('账户配置格式错误');
								const old = await 读取六账户配置(env);
								const accounts = old.accounts.map((item, i) => ({
									id: String(body.accounts[i]?.id || '').trim() || String(item?.id || '').trim(),
									token: String(body.accounts[i]?.token || '').trim() || String(item?.token || '').trim()
								}));
								const active = accounts.map((item, i) => ({ item, i })).filter(x => x.item.id || x.item.token);
								if (!active.length) throw new Error('至少填写一个账户的 Account ID 和 Token');
								const incomplete = active.find(x => !x.item.id || !x.item.token);
								if (incomplete) throw new Error('账户' + (incomplete.i + 1) + '的 Account ID 和 Token 必须同时填写');
								const validateAPI = 'https://api.cloudflare.com/client/v4/graphql';
								const validateQuery = 'query ValidateAccount(\\$accountTag: String!) { viewer { accounts(filter: {accountTag: \\$accountTag}) { accountTag } } }';
								for (const x of active) {
									const response = await fetch(validateAPI, { method: 'POST', headers: { 'Authorization': 'Bearer ' + x.item.token, 'X-Rate-Limit-Type': 'account-based', 'Accept': 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ query: validateQuery, variables: { accountTag: x.item.id } }) });
									const text = await response.text(); let data = {}; try { data = JSON.parse(text); } catch (e) {}
									if (!response.ok || data?.errors?.length || !data?.data?.viewer?.accounts?.length) {
										throw new Error('账户' + (x.i + 1) + '的 Account ID 或 Token 无效');
									}
								}
								const limitParts = String(body?.limits || '').split(',').map(v => Number(v.trim()));
								if (limitParts.length !== 6 || limitParts.some(v => !Number.isFinite(v) || v <= 0)) throw new Error('每日额度必须是6个正数，用逗号分隔');
								await 保存六账户配置(env, { accounts, limits: limitParts.map(v => Math.floor(v)) });
								return new Response(JSON.stringify({ success: true, msg: '六账户配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' } });
							} catch (err) { return new Response(JSON.stringify({ success: false, error: err.message }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' } }); }
						}
						return new Response('Method Not Allowed', { status: 405 });
					} else if (访问路径 === 'admin/get6accountusage') {// 六账户额度统计：账户1后台统一读取，客户端不接触Account ID/Token
					try {
						const Usage_JSON = await get6AccountWorkerUsage(env);
						return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' } });
					} catch (err) {
						const errorResponse = { success: false, msg: '六账户额度查询失败：' + err.message, error: err.message };
						return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' } });
					}
				} else if (访问路径 === 'admin/log.json') {// 读取日志内容