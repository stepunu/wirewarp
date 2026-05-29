/**
 * Thin React wrapper around uPlot for the Security Overview time-series.
 * Keeps the uPlot instance in a ref; resizes via ResizeObserver.
 */
import { useEffect, useRef } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'

export interface UPlotSeries {
  label: string
  stroke: string
  fill?: string
  width?: number
}

interface Props {
  timestamps: number[]   // unix seconds
  series: { values: number[]; opts: UPlotSeries }[]
  height?: number
}

export function UPlotChart({ timestamps, series, height = 140 }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const plotRef = useRef<uPlot | null>(null)

  useEffect(() => {
    const el = wrapRef.current
    if (!el) return

    const w = el.clientWidth || 600

    const uSeries: uPlot.Series[] = [
      {},
      ...series.map((s) => ({
        label: s.opts.label,
        stroke: s.opts.stroke,
        fill: s.opts.fill,
        width: s.opts.width ?? 1.5,
      })),
    ]

    const data: uPlot.AlignedData = [
      new Float64Array(timestamps),
      ...series.map((s) => new Float64Array(s.values)),
    ]

    const opts: uPlot.Options = {
      width: w,
      height,
      class: 'uplot-chart',
      cursor: { show: true },
      axes: [
        {
          stroke: 'var(--fg-3)',
          ticks: { stroke: 'var(--border-soft)' },
          grid: { stroke: 'var(--border-soft)', width: 0.5 },
        },
        {
          stroke: 'var(--fg-3)',
          ticks: { stroke: 'var(--border-soft)' },
          grid: { stroke: 'var(--border-soft)', width: 0.5 },
          size: 44,
        },
      ],
      series: uSeries,
    }

    plotRef.current = new uPlot(opts, data, el)

    const ro = new ResizeObserver(() => {
      if (plotRef.current && el.clientWidth > 0) {
        plotRef.current.setSize({ width: el.clientWidth, height })
      }
    })
    ro.observe(el)

    return () => {
      ro.disconnect()
      plotRef.current?.destroy()
      plotRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timestamps, series, height])

  return <div ref={wrapRef} style={{ width: '100%' }} />
}
