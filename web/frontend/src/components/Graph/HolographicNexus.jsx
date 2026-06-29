import React, { useRef, useEffect, useState, forwardRef, useImperativeHandle, useMemo } from 'react'
import ForceGraph3D from 'react-force-graph-3d'
import ForceGraph2D from 'react-force-graph-2d'
import * as THREE from 'three'
import SpriteText from 'three-spritetext'
import { createCyberGrid } from './ThreeEnvironment'

const HolographicNexus = forwardRef(({ data, onNodeClick, width, height }, ref) => {
  const fgRef = useRef()
  const [isMobile, setIsMobile] = useState(window.innerWidth < 1024)

  useImperativeHandle(ref, () => fgRef.current)

  // Shared geometries and materials for performance
  const geometries = useMemo(() => ({
    vulnerability: new THREE.OctahedronGeometry(4),
    domain: new THREE.SphereGeometry(6),
    host: new THREE.SphereGeometry(3.5),
  }), [])

  const materials = useMemo(() => ({
    domain: new THREE.MeshPhongMaterial({ color: 0x00d4ff, emissive: 0x00d4ff, emissiveIntensity: 0.3, transparent: true, opacity: 0.7, shininess: 50 }),
    host: new THREE.MeshPhongMaterial({ color: 0x7c3aed, emissive: 0x7c3aed, emissiveIntensity: 0.2, transparent: true, opacity: 0.7, shininess: 50 }),
    critical: new THREE.MeshPhongMaterial({ color: 0xef4444, emissive: 0xef4444, emissiveIntensity: 0.5, transparent: true, opacity: 0.8, shininess: 100 }),
    high: new THREE.MeshPhongMaterial({ color: 0xf97316, emissive: 0xf97316, emissiveIntensity: 0.4, transparent: true, opacity: 0.8, shininess: 100 }),
    medium: new THREE.MeshPhongMaterial({ color: 0xf59e0b, emissive: 0xf59e0b, emissiveIntensity: 0.4, transparent: true, opacity: 0.8, shininess: 100 }),
    low: new THREE.MeshPhongMaterial({ color: 0x3b82f6, emissive: 0x3b82f6, emissiveIntensity: 0.3, transparent: true, opacity: 0.8, shininess: 100 }),
  }), [])

  useEffect(() => {
    const handleResize = () => {
      setIsMobile(window.innerWidth < 1024)
    }
    window.addEventListener('resize', handleResize)
    
    if (fgRef.current && !isMobile) {
      const scene = fgRef.current.scene()
      // Add cyber grid if it doesn't exist
      if (!scene.getObjectByName('cyberGrid')) {
        const grid = createCyberGrid()
        grid.name = 'cyberGrid'
        scene.add(grid)
      }
      
      // Setup lights
      if (!scene.getObjectByName('ambientLight')) {
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.6)
        ambientLight.name = 'ambientLight'
        scene.add(ambientLight)
      }

      if (!scene.getObjectByName('pointLight')) {
        const pointLight = new THREE.PointLight(0x00d4ff, 1, 1000)
        pointLight.position.set(200, 200, 200)
        pointLight.name = 'pointLight'
        scene.add(pointLight)
      }
    }
    
    return () => window.removeEventListener('resize', handleResize)
  }, [isMobile])

  if (isMobile) {
    return (
      <ForceGraph2D
        ref={fgRef}
        graphData={data}
        width={width}
        height={height}
        backgroundColor="#00050a"
        nodeLabel={n => `${n.type}: ${n.label}`}
        linkColor={() => '#2d3b5a'}
        nodeColor={node => {
          if (node.type === 'vulnerability') {
            return node.severity === 'critical' ? '#ef4444' : 
                   node.severity === 'high' ? '#f97316' : 
                   node.severity === 'medium' ? '#f59e0b' : '#3b82f6'
          }
          return node.type === 'domain' ? '#00d4ff' : '#7c3aed'
        }}
        nodeRelSize={5}
        onNodeClick={onNodeClick}
        onEngineStop={() => fgRef.current?.zoomToFit(400, 30)}
      />
    )
  }

  return (
    <ForceGraph3D
      ref={fgRef}
      graphData={data}
      width={width}
      height={height}
      backgroundColor="#00050a"
      nodeLabel={n => `${n.type}: ${n.label}`}
      linkDirectionalParticles={3}
      linkDirectionalParticleSpeed={0.006}
      linkDirectionalParticleWidth={2}
      linkColor={() => '#2a3b5c'}
      cooldownTicks={150}
      d3AlphaDecay={0.02}
      d3VelocityDecay={0.5}
      onEngineStop={() => fgRef.current?.zoomToFit(1000, 100)}
      nodeThreeObject={node => {
        const isVuln = node.type === 'vulnerability'
        const isDomain = node.type === 'domain'
        
        const group = new THREE.Group()
        
        // 1. Add the shape
        let mesh;
        if (isVuln) {
          const material = materials[node.severity] || materials.low
          mesh = new THREE.Mesh(geometries.vulnerability, material.clone()) // Clone to allow per-node animation
          mesh.userData.isVulnerability = true
          mesh.userData.baseEmissive = material.emissiveIntensity
        } else {
          const material = isDomain ? materials.domain : materials.host
          const geometry = isDomain ? geometries.domain : geometries.host
          mesh = new THREE.Mesh(geometry, material)
        }
        group.add(mesh)

        // 2. Add the Billboard Label
        const sprite = new SpriteText(node.label || node.id)
        sprite.color = isVuln ? '#fff' : '#cbd5e1'
        sprite.textHeight = isVuln ? 5 : 3.5
        sprite.position.y = isVuln ? 12 : 10
        sprite.backgroundColor = 'rgba(0,0,0,0.7)'
        sprite.padding = 3
        sprite.borderRadius = 4
        group.add(sprite)
        
        return group
      }}
      nodeThreeObjectExtend={false}
      onNodeClick={onNodeClick}
      onEngineTick={() => {
        if (!fgRef.current) return
        const { nodes } = data
        if (!nodes) return
        
        const t = Date.now() / 1000
        const scale = 1 + Math.sin(t * 3) * 0.12
        const glow = 0.5 + Math.sin(t * 3) * 0.3
        
        nodes.forEach(node => {
          if (node.type === 'vulnerability' && node.__threeObj) {
            const mesh = node.__threeObj.children.find(c => c.userData.isVulnerability)
            if (mesh) {
              mesh.scale.set(scale, scale, scale)
              mesh.material.emissiveIntensity = glow
              mesh.material.opacity = 0.7 + Math.sin(t * 3) * 0.1
            }
          }
        })
      }}
    />
  )
})

export default HolographicNexus
