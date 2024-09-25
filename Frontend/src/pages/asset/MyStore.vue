<template lang="">
  <AssetHeader />
  <div class="container">
    <StoreInfo class="mb-5" />
    <MyAsset class="mb-5" />
    <MyGraph class="mb-5" />
  </div>
</template>

<script>
import StoreInfo from '@/components/asset/StoreInfo.vue';
import MyAsset from '@/components/asset/MyAsset.vue';
import MyGraph from '@/components/asset/MyGraph.vue';
import AssetHeader from '@/components/asset/AssetHeader.vue';

export default {
  name: 'MyStore',
  components: {
    StoreInfo,
    MyAsset,
    MyGraph,
    AssetHeader,
  },
  setup() {
    return {};
  },
};
</script>

<style scoped></style>
