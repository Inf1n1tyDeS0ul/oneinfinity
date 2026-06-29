import * as THREE from 'three'

/**
 * Creates a semi-transparent cyber-grid for the 3D scene background.
 */
export function createCyberGrid() {
  const size = 10000;
  const divisions = 100;
  const gridHelper = new THREE.GridHelper(size, divisions, 0x00d4ff, 0x00d4ff);
  gridHelper.position.y = -200;
  gridHelper.material.opacity = 0.15;
  gridHelper.material.transparent = true;
  return gridHelper;
}
