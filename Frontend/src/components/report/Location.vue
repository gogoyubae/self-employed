<template>
  <div class="container">
    <div class="title">추천 위치</div>
    <div class="row">
      <div class="col-6" style="width: 60%">
        <div id="map" style="height: 400px"></div>
      </div>
      <div class="col-6" style="width: 40%">
        <div style="height: 400px; border: solid 1px">빈칸 입니다</div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  mounted() {
    const script = document.createElement('script');
    script.src =
      '//dapi.kakao.com/v2/maps/sdk.js?appkey=09118387dc78b55b2c58f3876095c5d2&autoload=false';
    script.onload = () => {
      kakao.maps.load(() => {
        var container = document.getElementById('map');
        var options = {
          center: new kakao.maps.LatLng(33.450701, 126.570667),
          level: 3,
        };

        var map = new kakao.maps.Map(container, options);
      });
    };
    document.head.appendChild(script);
  },
};
</script>

<style scoped>
.container {
  padding: 0px 80px 15px 80px;
}

.title {
  margin: -14px 0px -14px 0px;
  position: relative;
  top: -18px;
  font-size: 25px;
  font-weight: bold;
}
</style>
