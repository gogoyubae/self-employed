<template>
  <img
    src="../../assets/img/simul/sumul_cut.jpg"
    alt=""
    style="width: 100%; height: 712px"
  />
</template>

<script>
export default {
  mounted() {
    // 컴포넌트가 렌더링된 후 자동으로 실행
    this.hideDiv();
  },
  methods: {
    hideDiv() {
      // 특정 클래스명으로 요소 선택 후 속성 부여
      const header = document.querySelector('.he-visible');
      const footer = document.querySelector('.fo-visible');

      header.style.display = 'none'; // display: none 적용
      footer.style.display = 'none';
    },
  },
};
</script>
