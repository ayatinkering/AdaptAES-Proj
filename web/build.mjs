import {build,context} from 'esbuild';
import {cp,mkdir} from 'node:fs/promises';
await mkdir('dist',{recursive:true});
await cp('public','dist',{recursive:true});
await cp('index.html','dist/index.html');
const options={entryPoints:['src/main.jsx'],bundle:true,minify:true,external:['/fonts/*'],outdir:'dist/assets',entryNames:'app',loader:{'.woff2':'file'},define:{'process.env.NODE_ENV':'"production"'},target:['es2022'],sourcemap:false};
if(process.argv.includes('--watch')){const ctx=await context(options);await ctx.watch();console.log('Watching frontend. Run python3 -m api.server from the repository root.');}
else await build(options);
