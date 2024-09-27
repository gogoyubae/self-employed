<template>
  <div>
    <Header />
    <router-view></router-view>
    <Footer />
  </div>
</template>

<script setup>
import Header from '@/components/common/Header.vue';
import Footer from '@/components/common/Footer.vue';
import './assets/css/fonts.css';
</script>

<style>
@import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css');

@font-face {
  font-family: 'Pretendard-Black';
  src: url('@/assets/fonts/Pretendard-Black.otf') format('opentype');
  font-weight: 900;
  font-style: normal;
}

body {
  font-family: 'Pretendard-Black', sans-serif;
}
</style>
