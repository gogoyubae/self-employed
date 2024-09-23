<template lang="">
  <div>
    <StoreInfo />
    <MyAsset class="mt-20" />
  </div>
</template>

<script>
import StoreInfo from '../../components/asset/StoreInfo.vue';
import MyAsset from '../../components/asset/MyAsset.vue';

export default {
  name: 'MyStore',
  components: {
    StoreInfo,
    MyAsset,
  },
  setup() {
    return {
    };
  }
};
</script>

<style scoped></style>
