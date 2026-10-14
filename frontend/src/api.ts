import axios from 'axios';
export const api=axios.create({baseURL:'/api',withCredentials:true});
export function setCsrf(token:string){api.defaults.headers.common['X-CSRF-Token']=token;}
export function errorText(e:unknown){if(axios.isAxiosError(e)){const d=e.response?.data?.detail;return typeof d==='string'?d: d?JSON.stringify(d):'Cannot reach the server. Check that FastAPI is running.';}return e instanceof Error?e.message:'Something went wrong';}
export function downloadJSON(value:unknown,name:string){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
export const defaultConfig={duration:30,stride:10,episode_gap:60,threshold:.55,weights:{D:.35,C:.2,P:.25,X:.2,B:.2},min_identity_coverage:.8,incomplete:'include',late_policy:'sort_recorded',rename_enabled:true,destructive_operations:['Write','Rename','Delete']};
