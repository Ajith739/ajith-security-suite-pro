/* ============================================================
   Gracewell Security Suite Pro — Hero Birds Animation
   Three.js low-poly flocking birds drawn onto the hero canvas.
   Loaded as an ES module (deferred by default).
   ============================================================ */

(async () => {
    'use strict';

    const hero = document.querySelector('.hero');
    const canvas = document.getElementById('heroBirds');
    if (!hero || !canvas || canvas.__gwqshHeroBirds) return;

    // One owner per canvas, including while the bundled module is loading.
    let disposed = false, raf = 0, readyRaf = 0;
    let renderer, mat, scene;
    const birds = [], observers = [], listeners = [];
    const owner = { dispose };
    canvas.__gwqshHeroBirds = owner;

    function listen(target, type, handler) {
        target.addEventListener(type, handler);
        listeners.push([target, type, handler]);
    }
    function observe(observer, target, options) {
        observers.push(observer);
        observer.observe(target, options);
    }
    function dispose() {
        if (disposed) return;
        disposed = true;
        stop();
        cancelAnimationFrame(readyRaf);
        observers.forEach(observer => observer.disconnect());
        listeners.forEach(([target, type, handler]) => target.removeEventListener(type, handler));
        birds.forEach(bird => {
            scene.remove(bird.mesh);
            bird.mesh.geometry.dispose();
        });
        mat?.dispose();
        renderer?.dispose();
        renderer?.forceContextLoss();
        canvas.classList.remove('ready');
        if (canvas.__gwqshHeroBirds === owner) delete canvas.__gwqshHeroBirds;
    }
    observe(new MutationObserver(() => {
        if (!hero.isConnected || !canvas.isConnected || !hero.contains(canvas)) dispose();
    }), document.documentElement, { childList: true, subtree: true });
    listen(window, 'pagehide', event => event.persisted ? stop() : dispose());

    /* ----------------------------------------------------------
       Load bundled Three.js r160 locally. If it fails, silently remove
       the canvas so the hero still looks right.
       ---------------------------------------------------------- */
    let THREE;
    try {
        THREE = await import('../vendor/three/three.module.js');
        if (disposed) return;
    } catch (e) {
        dispose();
        canvas.remove();
        return;
    }

    const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
    let reduce = motionPreference.matches;

    /* ----------------------------------------------------------
       Renderer
       ---------------------------------------------------------- */
    try {
        renderer = new THREE.WebGLRenderer({
            canvas,
            alpha: true,
            antialias: true,
            powerPreference: 'low-power'
        });
    } catch (e) {
        dispose();
        canvas.remove();
        return;
    }

    renderer.setPixelRatio(Math.min(devicePixelRatio || 1, innerWidth < 768 ? 1.5 : 2));
    renderer.setClearColor(0x000000, 0);

    /* ----------------------------------------------------------
       Scene + camera
       ---------------------------------------------------------- */
    scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, 1, 1, 2000);
    camera.position.z = 400;

    /* ----------------------------------------------------------
       Shared material + theme-aware colour
       ---------------------------------------------------------- */
    mat = new THREE.MeshBasicMaterial({
        color: 0x1F2A5A,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: .6
    });

    const setColor = () => {
        if (disposed) return;
        const dark = document.documentElement.dataset.theme === 'dark';
        mat.color.set(dark ? 0xC9D4FF : 0x1F2A5A);
        mat.opacity = dark ? .7 : .8;
        if (reduce) draw();
    };

    observe(new MutationObserver(setColor), document.documentElement, {
        attributes: true,
        attributeFilter: ['data-theme']
    });

    /* ----------------------------------------------------------
       Low-poly bird geometry
       Body + two wings, nose pointing +X.
       Wing tips are vertices 3 and 6 (indices 10 and 19 in the
       flattened array).
       ---------------------------------------------------------- */
    const BASE = new Float32Array([
        5, 0, 0, -5, 0, 0, -5, -2, 1,
        0, 2, -6, -3, 0, 0, 2, 0, 0,
        0, 2, 6, 2, 0, 0, -3, 0, 0
    ]);

    /* Bounds used for wrapping / soft containment */
    const B = { x: 1, y: 1, z: 60 };

    const V = THREE.Vector3;
    const rand = (a, b) => a + Math.random() * (b - a);

    /* Fewer birds on smaller screens */
    const COUNT = innerWidth < 640 ? 4 : innerWidth < 1100 ? 7 : 10;

    for (let i = 0; i < COUNT; i++) {
        const g = new THREE.BufferGeometry();
        g.setAttribute('position', new THREE.BufferAttribute(BASE.slice(), 3));

        const mesh = new THREE.Mesh(g, mat);
        mesh.scale.setScalar(rand(1.0, 1.5));
        scene.add(mesh);

        birds.push({
            mesh,
            pos: g.attributes.position,
            p: new V(),
            v: new V(),
            a: new V(),
            phase: rand(0, Math.PI * 2),
            flap: rand(.85, 1.15)
        });
    }

    /* ----------------------------------------------------------
       Resize handling
       ---------------------------------------------------------- */
    function resize() {
        if (disposed) return false;
        const w = canvas.clientWidth;
        const h = canvas.clientHeight;
        if (!w || !h) return false;

        renderer.setPixelRatio(Math.min(devicePixelRatio || 1, innerWidth < 768 ? 1.5 : 2));
        renderer.setSize(w, h, false);
        camera.aspect = w / h;
        camera.updateProjectionMatrix();

        B.y = Math.tan(THREE.MathUtils.degToRad(22.5)) * camera.position.z;
        B.x = B.y * camera.aspect;
        return true;
    }

    resize();

    /* ----------------------------------------------------------
       Initial positions + velocities
       ---------------------------------------------------------- */
    const dir = Math.random() < .5 ? 1 : -1;

    birds.forEach(b => {
        b.p.set(
            rand(-B.x * .8, B.x * .8),
            rand(-B.y * .1, B.y * .6),
            rand(-B.z, B.z)
        );
        b.v.set(
            dir * rand(.8, 1.6),
            rand(-.2, .2),
            rand(-.4, .4)
        );
    });

    /* ----------------------------------------------------------
       Pointer interaction — birds gently avoid the cursor
       ---------------------------------------------------------- */
    const ptr = { x: 0, y: 0, on: false };

    listen(hero, 'pointermove', e => {
        const r = canvas.getBoundingClientRect();

        if (e.clientX < r.left || e.clientX > r.right ||
            e.clientY < r.top || e.clientY > r.bottom) {
            ptr.on = false;
            return;
        }

        ptr.x = ((e.clientX - r.left) / r.width * 2 - 1) * B.x;
        ptr.y = -((e.clientY - r.top) / r.height * 2 - 1) * B.y;
        ptr.on = true;
    });

    listen(hero, 'pointerleave', () => { ptr.on = false; });

    /* ----------------------------------------------------------
       Boids flocking
       - alignment, cohesion, separation
       - soft containment to the hero bounds
       - cursor avoidance
       - wing flap driven by vertical rotation + phase
       ---------------------------------------------------------- */
    const MAX = 1.8;
    const MIN = .9;
    const F = .035;
    const R = 60;   // neighbour radius
    const SEP = 24;   // separation radius

    const ali = new V();
    const coh = new V();
    const sep = new V();
    const tmp = new V();

    function step(dt) {
        const xM = B.x * .88;
        const yT = B.y * .78;
        const yB = -B.y * .35;

        /* ---- compute steering accelerations ---- */
        for (const b of birds) {
            ali.set(0, 0, 0);
            coh.set(0, 0, 0);
            sep.set(0, 0, 0);

            let n = 0;
            let ns = 0;

            for (const o of birds) {
                if (o === b) continue;

                const d = b.p.distanceTo(o.p);
                if (d < R) {
                    ali.add(o.v);
                    coh.add(o.p);
                    n++;

                    if (d < SEP && d > 0) {
                        tmp.subVectors(b.p, o.p).divideScalar(d * d);
                        sep.add(tmp);
                        ns++;
                    }
                }
            }

            b.a.set(0, 0, 0);

            if (n) {
                /* alignment */
                ali.divideScalar(n).setLength(MAX).sub(b.v).clampLength(0, F);
                b.a.add(ali);

                /* cohesion */
                coh.divideScalar(n).sub(b.p);
                if (coh.lengthSq() > 1e-6) {
                    coh.setLength(MAX).sub(b.v).clampLength(0, F * .7);
                    b.a.add(coh);
                }
            }

            /* separation */
            if (ns && sep.lengthSq() > 0) {
                sep.setLength(MAX).sub(b.v).clampLength(0, F * 1.8);
                b.a.add(sep);
            }

            /* soft containment */
            if (b.p.x > xM) b.a.x -= (b.p.x - xM) * .004;
            else if (b.p.x < -xM) b.a.x += (-xM - b.p.x) * .004;

            if (b.p.y > yT) b.a.y -= (b.p.y - yT) * .004;
            else if (b.p.y < yB) b.a.y += (yB - b.p.y) * .004;

            if (b.p.z > B.z) b.a.z -= (b.p.z - B.z) * .004;
            else if (b.p.z < -B.z) b.a.z += (-B.z - b.p.z) * .004;

            /* cursor avoidance */
            if (ptr.on) {
                tmp.set(b.p.x - ptr.x, b.p.y - ptr.y, 0);
                const d = tmp.length();
                if (d < 90 && d > 0) {
                    tmp.setLength((90 - d) * .006);
                    b.a.add(tmp);
                }
            }
        }

        /* ---- integrate ---- */
        for (const b of birds) {
            b.v.addScaledVector(b.a, dt);

            const sp = b.v.length();
            if (sp > MAX) b.v.setLength(MAX);
            else if (sp < MIN) b.v.setLength(MIN);

            b.p.addScaledVector(b.v, dt);

            /* wrap if it drifts far out */
            if (Math.abs(b.p.x) > B.x * 1.6 || Math.abs(b.p.y) > B.y * 1.6) {
                b.p.set(rand(-B.x * .5, B.x * .5), rand(0, B.y * .5), 0);
            }

            const m = b.mesh;
            m.position.copy(b.p);

            /* orient along velocity vector */
            m.rotation.y = Math.atan2(-b.v.z, b.v.x);
            m.rotation.z = Math.asin(
                THREE.MathUtils.clamp(b.v.y / b.v.length(), -1, 1)
            );

            /* wing flap */
            b.phase += dt * (.2 + Math.max(0, m.rotation.z) * .6) * b.flap;
            const wy = Math.sin(b.phase) * 5;

            const arr = b.pos.array;
            arr[10] = wy; // left wing tip
            arr[19] = wy; // right wing tip
            b.pos.needsUpdate = true;
        }
    }

    /* ----------------------------------------------------------
       Draw loop
       ---------------------------------------------------------- */
    const draw = () => { if (!disposed) renderer.render(scene, camera); };
    setColor();

    let last = 0;
    let heroVisible = true;

    const frame = t => {
        if (disposed) return;
        raf = requestAnimationFrame(frame);
        const dt = Math.min((t - last) / 16.667, 3);
        last = t;
        step(dt);
        draw();
    };

    const start = () => {
        if (!disposed && !raf && !reduce && heroVisible && !document.hidden) {
            last = performance.now();
            raf = requestAnimationFrame(frame);
        }
    };

    function stop() {
        cancelAnimationFrame(raf);
        raf = 0;
    }

    /* ----------------------------------------------------------
       Observers: resize, visibility, tab hidden
       ---------------------------------------------------------- */
    observe(new ResizeObserver(() => {
        if (resize() && reduce) draw();
    }), canvas);

    observe(new IntersectionObserver(([e]) => {
        if (disposed) return;
        heroVisible = e.isIntersecting;
        heroVisible ? start() : stop();
    }), hero);

    listen(document, 'visibilitychange', () => {
        document.hidden ? stop() : start();
    });

    listen(motionPreference, 'change', () => {
        reduce = motionPreference.matches;
        if (reduce) { stop(); draw(); } else start();
    });

    listen(window, 'pageshow', event => { if (event.persisted) start(); });

    /* ----------------------------------------------------------
       Kick off
       ---------------------------------------------------------- */
    if (reduce) {
        /* Step a bunch of frames instantly so the flock settles,
           then draw a single static frame. */
        for (let i = 0; i < 120; i++) step(1);
        draw();
    } else {
        start();
    }

    readyRaf = requestAnimationFrame(() => { if (!disposed) canvas.classList.add('ready'); });
})();