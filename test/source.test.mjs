import test from 'node:test';
import assert from 'node:assert/strict';
import {createSource} from '../src/source.mjs';
import {inspect,readRaw} from '../src/client.mjs';

async function withSource(callback){const source=await createSource();try{return await callback(source);}finally{await source.close();}}
function access(source){return async(path,options={})=>{const response=await fetch(source.url+path,{method:options.method||'GET',body:options.body===undefined?undefined:JSON.stringify(options.body),signal:AbortSignal.timeout(4000)});const text=await response.text();let value=text;try{value=JSON.parse(text);}catch{}return {status:response.status,value};};}
test('来源存活与单次目录读取',()=>withSource(async source=>{const api=access(source);assert.equal((await api('/health')).value.status,'ok');assert.ok(Object.keys(await inspect(source.url)).length>0);assert.ok((await readRaw(source.url,'/inventory')).length>0);}));
test('未知路径与坏控制请求明确拒绝',()=>withSource(async source=>{const api=access(source);assert.equal((await api('/missing')).status,404);const invalid=await fetch(source.url+'/control',{method:'POST',body:'not-json'});assert.equal(invalid.status,400);}));
test('来源领域契约的状态变化',()=>withSource(async source=>{const api=access(source);const {announcement,header,compressedName}=await import('../src/discovery.mjs');const value=(await api('/state')).value;assert.equal(header(announcement(value)).answers,5);assert.equal(compressedName.at(-2),0xc0);const dgram=await import('node:dgram');const socket=dgram.createSocket('udp4');await new Promise(resolve=>socket.bind(0,'127.0.0.1',resolve));try{const received=new Promise(resolve=>socket.once('message',resolve));await api('/emit',{method:'POST',body:{port:socket.address().port}});assert.equal(header(await received).answers,5);}finally{socket.close();}}));

