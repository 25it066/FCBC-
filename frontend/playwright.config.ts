import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',testMatch:'**/*.pw.ts',use:{baseURL:process.env.FCBC_URL||'http://127.0.0.1:8000',headless:true},timeout:60000});
