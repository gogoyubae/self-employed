export const store_data_bar = {
  labels: ['1월', '2월', '3월', '4월', '5월', '6월'],
  datasets: [
    {
      label: 'Data One',
      backgroundColor: '#fcd752',
      data: [40, 20, 12, 39, 10, 120], // 'data_bar' 대신 'data'
    },
  ],
};


export const store_barOptions = {
  responsive: true,
  maintainAspectRatio: false, // CSS 높이 사용
  scales: {
    x: {
      grid: {
        color: 'rgba(255, 255, 255, 0.3)',
        lineWidth: 1,
      },
      ticks: {
        // x축 레이블을 보여주려면 display: true로 설정합니다.
        display: true, // x축 레이블 보임
        autoSkip: true, // 레이블 자동 생략
        maxRotation: 0, // 최대 회전 각도 (0도: 수평)
        minRotation: 0, // 최소 회전 각도 (0도: 수평)
        padding: 10, // 레이블과 x축 사이의 간격 (픽셀)
      },
    },
  },
  barThickness: 20,
  plugins: {
    legend: {
      display: false, // 레전드 숨김
    },
  },
};