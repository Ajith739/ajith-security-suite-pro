/* Security Suite Pro's small local animation adapter. Uses native browser animation APIs. */
(function () {
    'use strict';
    const reserved = new Set(['duration','delay','stagger','ease','onUpdate','onComplete','clearProps','repeat','transformOrigin','transformBox','svgOrigin']);
    const transforms = new Set(['x','y','scale','rotation','rotate','rotationX']);
    const targets = value => typeof value === 'string' ? [...document.querySelectorAll(value)] : value instanceof NodeList || Array.isArray(value) ? [...value] : value ? [value] : [];
    const duration = options => Math.max(0, Number(options.duration || .4)) * 1000;
    function frame(el, values, fallback) {
        const result = {}, parts = [];
        Object.keys(values).forEach(key => {
            if (reserved.has(key)) return;
            const value = values[key];
            if (transforms.has(key)) {
                if (key === 'x' || key === 'y') parts.push('translate' + key.toUpperCase() + '(' + value + 'px)');
                else if (key === 'scale') parts.push('scale(' + value + ')');
                else parts.push((key === 'rotationX' ? 'rotateX' : 'rotate') + '(' + value + 'deg)');
            } else result[key] = value;
        });
        if (parts.length) result.transform = parts.join(' ');
        if (fallback) Object.keys(result).forEach(key => { result[key] = key === 'transform' ? 'none' : getComputedStyle(el)[key]; });
        return result;
    }
    function run(value, start, end, mode) {
        const options = end || start;
        targets(value).forEach((target,index) => {
            const stagger = typeof options.stagger === 'object' ? options.stagger.each : options.stagger;
            const delay = (Number(options.delay || 0) + index * Number(stagger || 0)) * 1000;
            if (!(target instanceof Element)) {
                const original = {};
                Object.keys(options).filter(key => !reserved.has(key)).forEach(key => { original[key] = Number(target[key] || 0); });
                const began = performance.now() + delay;
                function tick(now) {
                    const progress = Math.max(0, Math.min(1, (now - began) / duration(options)));
                    const eased = 1 - Math.pow(1 - progress, 3);
                    Object.keys(original).forEach(key => { target[key] = original[key] + (Number(options[key]) - original[key]) * eased; });
                    if (options.onUpdate) options.onUpdate();
                    if (progress < 1) requestAnimationFrame(tick); else if (options.onComplete) options.onComplete();
                }
                requestAnimationFrame(tick); return;
            }
            const computed = frame(target, options, true);
            const first = mode === 'from' || mode === 'fromTo' ? frame(target, start) : computed;
            const last = mode === 'from' ? computed : frame(target, end || start);
            if (options.transformOrigin) { first.transformOrigin = last.transformOrigin = options.transformOrigin; }
            const finish = () => {
                if (mode !== 'from') Object.entries(last).forEach(([key,val]) => { target.style[key] = val; });
                if (options.onComplete) options.onComplete();
            };
            if (!target.animate) { finish(); return; }
            const animation = target.animate([first,last], {
                duration: duration(options), delay, easing: 'cubic-bezier(.2,.65,.3,1)',
                iterations: Number(options.repeat || 0) + 1, fill: 'backwards'
            });
            animation.onfinish = finish;
        });
    }
    window.GWQSH_Motion = {
        from: (target,options) => run(target,options,null,'from'),
        to: (target,options) => run(target,null,options,'to'),
        fromTo: (target,start,end) => run(target,start,end,'fromTo'),
        timeline: function (options) {
            let offset = 0;
            const chain = {};
            chain.from = function (target,values,position) {
                const overlap = typeof position === 'string' && position.startsWith('-=') ? Number(position.slice(2)) : 0;
                offset = Math.max(0,offset - overlap);
                run(target,Object.assign({},options && options.defaults,values,{delay: offset + Number(values.delay || 0)}),null,'from');
                offset += Number(values.duration || .4);
                return chain;
            };
            return chain;
        }
    };
})();
