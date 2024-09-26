<template>
<div>
        <div>
          <h4 class="mb-2">매출추이</h4>
        </div> 
        <div class="">
          <canvas id="bar-chart2" style="height: 200px"></canvas>
        </div>
      </div>
      
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { Chart } from 'chart.js/auto';
import {
  store_data_bar,
  store_barOptions,
} from '@/assets/js/mainStoreChart.js';

let barChartInstance = ref(null); // 막대 차트 인스턴스

onMounted(() => {
const barCtx = document.getElementById('bar-chart2').getContext('2d');
  // Chart.js를 사용하여 바 차트 생성
  barChartInstance.value = new Chart(barCtx, {
    type: 'bar',
    data: store_data_bar,
    options: store_barOptions,
  });
});
</script>

<style scoped>
canvas {
  max-width: 100%;
  height: auto;
}

</style>
