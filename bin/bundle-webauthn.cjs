/* Deterministic runtime bundling after composer install/update. No network access. */
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),source=path.join(process.env.GWQSH_COMPOSER_VENDOR_DIR||path.join(root,'vendor'),'lbuchs/webauthn'),target=path.join(root,'includes/vendor/webauthn');
const dependency=JSON.parse(fs.readFileSync(path.join(root,'composer.lock'),'utf8')).packages.find(p=>p.name==='lbuchs/webauthn');
if(!dependency)throw new Error('The verifier must be present in composer.lock.');
if(!fs.existsSync(path.join(source,'src/WebAuthn.php')))throw new Error('Install the locked Composer dependency before bundling.');
function copy(dir,dest){fs.mkdirSync(dest,{recursive:true});for(const item of fs.readdirSync(dir,{withFileTypes:true})){if(item.isSymbolicLink())throw new Error('Dependency symlinks are forbidden.');const from=path.join(dir,item.name),to=path.join(dest,item.name);if(item.isDirectory())copy(from,to);else if(item.name.endsWith('.php')){let text=fs.readFileSync(from,'utf8');text=text.replaceAll('lbuchs\\\\WebAuthn','GracewellSecuritySuitePro\\\\Vendor\\\\WebAuthn').replaceAll('lbuchs\\WebAuthn','GracewellSecuritySuitePro\\Vendor\\WebAuthn');fs.writeFileSync(to,text);}}}
copy(path.join(source,'src'),path.join(target,'src'));fs.copyFileSync(path.join(source,'LICENSE'),path.join(target,'LICENSE'));
fs.writeFileSync(path.join(target,'BUNDLED-NOTICE.txt'),'lbuchs/webauthn '+dependency.version+' — MIT\nSource: https://github.com/lbuchs/WebAuthn\nOnly runtime PHP and LICENSE are bundled. Namespace scoped to GracewellSecuritySuitePro\\Vendor\\WebAuthn to avoid conflicts with other plugins. No verification logic changed.\n');
console.log('Bundled namespace-isolated WebAuthn runtime and MIT license.');
