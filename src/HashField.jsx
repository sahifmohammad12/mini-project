import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";

const N = 8; // 8 x 8 = 64 blocks, one per character of a SHA-256 fingerprint
const GAP = 1;

function useMedia(query) {
  const [match, setMatch] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const m = window.matchMedia(query);
    const on = (e) => setMatch(e.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, [query]);
  return match;
}

function Field({ reg, cur, dark, still }) {
  const mesh = useRef();
  const group = useRef();
  const dirty = useRef(true);
  const heights = useRef(new Float32Array(N * N).fill(0.05));
  const dummy = useMemo(() => new THREE.Object3D(), []);
  const ink = useMemo(() => new THREE.Color(dark ? "#ffffff" : "#000000"), [dark]);
  const mute = useMemo(() => new THREE.Color(dark ? "#444444" : "#c8c8c8"), [dark]);

  useEffect(() => {
    dirty.current = true;
  }, [reg, cur, ink, mute]);

  useFrame((state, dt) => {
    const m = mesh.current;
    if (!m) return;
    const ready = reg.length === 64 && cur.length === 64;

    if (dirty.current) {
      for (let i = 0; i < N * N; i++) {
        m.setColorAt(i, ready && reg[i] !== cur[i] ? mute : ink);
      }
      m.instanceColor.needsUpdate = true;
      dirty.current = false;
    }

    const h = heights.current;
    const k = Math.min(1, dt * 4);
    for (let i = 0; i < N * N; i++) {
      const diff = ready && reg[i] !== cur[i];
      const target = ready ? 0.25 + (parseInt(cur[i], 16) / 15) * 2.2 + (diff ? 0.4 : 0) : 0.05;
      h[i] += (target - h[i]) * k;
      dummy.position.set(((i % N) - (N - 1) / 2) * GAP, h[i] / 2, (Math.floor(i / N) - (N - 1) / 2) * GAP);
      dummy.scale.set(1, h[i], 1);
      dummy.updateMatrix();
      m.setMatrixAt(i, dummy.matrix);
    }
    m.instanceMatrix.needsUpdate = true;

    const g = group.current;
    if (!still) g.rotation.y += dt * 0.12;
    g.rotation.x = THREE.MathUtils.lerp(g.rotation.x, state.pointer.y * 0.1, 0.05);
  });

  return (
    <group ref={group} position={[0, -1, 0]}>
      <instancedMesh ref={mesh} args={[null, null, N * N]} frustumCulled={false}>
        <boxGeometry args={[0.82, 1, 0.82]} />
        <meshStandardMaterial color="#ffffff" roughness={0.35} metalness={0} />
      </instancedMesh>
    </group>
  );
}

export default function HashField({ reg, cur }) {
  const dark = useMedia("(prefers-color-scheme: dark)");
  const still = useMedia("(prefers-reduced-motion: reduce)");
  return (
    <Canvas dpr={[1, 2]} camera={{ position: [14, 12, 14], fov: 28 }} gl={{ alpha: true, antialias: true }}>
      <ambientLight intensity={dark ? 0.7 : 1.1} />
      <directionalLight position={[6, 10, 4]} intensity={dark ? 2 : 2.4} />
      <Field reg={reg} cur={cur} dark={dark} still={still} />
    </Canvas>
  );
}
